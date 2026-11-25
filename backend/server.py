"""Serve the local operator console and its read-only API."""

import argparse
import json
import logging
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import Future
from http import HTTPStatus
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from urllib.parse import urlsplit

from backend.haiku import HaikuModels, HaikuRequestError
from backend.models import MODELS, ReleaseModels, parse_features
from backend.capture_feed import CaptureFeed
from backend.lab_monitor import LabChecks
from backend.simulation import SCENARIOS, describe_scenario, run_scenario
from backend.store import read_overview
from backend.simulation_store import save_simulation
from cloud.publish import AwsError
from experiments.verify_claude_traffic import ask_claude


ROOT = Path(__file__).resolve().parents[1]
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/favicon.ico": ("favicon.ico", "image/vnd.microsoft.icon"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/live_lab.js": ("live_lab.js", "text/javascript; charset=utf-8"),
    "/traffic.js": ("traffic.js", "text/javascript; charset=utf-8"),
    "/topology.js": ("topology.js", "text/javascript; charset=utf-8"),
    "/vendor/three/three.module.min.js": ("node_modules/three/build/three.module.min.js", "text/javascript; charset=utf-8"),
    "/vendor/three/three.core.min.js": ("node_modules/three/build/three.core.min.js", "text/javascript; charset=utf-8"),
}
LOGGER = logging.getLogger(__name__)


def load_release_models(model_load):
    LOGGER.info("Loading release models in the background.")
    try:
        models = ReleaseModels(ROOT / "ai/models")
    except Exception:
        LOGGER.exception("Could not initialize release models")
        model_load.set_result(None)
    else:
        model_load.set_result(models)
        LOGGER.info("Release models ready: %d of %d.", len(models.models), len(MODELS))


class ConsoleHandler(BaseHTTPRequestHandler):
    timeout = 10

    def log_error(self, format, *args):
        # Browsers can open a connection and leave it idle without sending a request line.
        if format == "Request timed out: %r" and not getattr(self, "raw_requestline", b""):
            return
        super().log_error(format, *args)

    def write_response(self, status, content, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

    def send_json(self, status, payload):
        content = json.dumps(payload, allow_nan=False).encode()
        self.write_response(status, content, "application/json; charset=utf-8")

    def valid_host(self):
        port = self.server.server_port
        allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if port == 80:
            allowed_hosts.update(("127.0.0.1", "localhost"))
        return self.headers.get("Host") in allowed_hosts

    def do_GET(self):
        if not self.valid_host():
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Use the local console URL."})
            return

        path = urlsplit(self.path).path
        if path in STATIC:
            filename, content_type = STATIC[path]
            asset = ROOT / "frontend" / filename
            if not asset.is_file():
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "Asset not installed."})
                return
            self.write_response(HTTPStatus.OK, asset.read_bytes(), content_type)
        elif path == "/api/health":
            model_load = self.server.model_load
            loading = not model_load.done()
            models = None if loading else model_load.result()
            status = models.status if models is not None else {
                key: {"name": name, "ready": False} for key, (name, *_) in MODELS.items()
            }
            self.send_json(HTTPStatus.OK, {"status": "ready", "models_loading": loading, "models": status,
                                           "simulation_storage": bool(getattr(self.server, "simulation_storage", None))})
        elif path == "/api/overview":
            try:
                overview = read_overview(self.server.database)
            except sqlite3.Error:
                LOGGER.exception("Could not read the incident store")
                self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "The incident store could not be read."})
                return
            self.send_json(HTTPStatus.OK, overview)
        elif path == "/api/lab":
            self.send_json(HTTPStatus.OK, self.server.lab_checks.snapshot())
        elif path == "/api/packets":
            self.send_json(HTTPStatus.OK, {**self.server.capture_feed.snapshot(),
                                           "ai_verification": bool(getattr(self.server, "capture_ai", None))})
        elif path == "/api/simulations":
            scenarios = [describe_scenario(key, scenario) for key, scenario in SCENARIOS.items()]
            self.send_json(HTTPStatus.OK, {"scenarios": scenarios})
        elif path.startswith("/api/simulations/") and (key := path.removeprefix("/api/simulations/")) in SCENARIOS:
            self.send_json(HTTPStatus.OK, run_scenario(key))
        else:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Page not found."})

    do_HEAD = do_GET

    def do_POST(self):
        origin = self.headers.get("Origin")
        if not self.valid_host() or (origin and origin != f"http://{self.headers['Host']}"):
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Use the local console URL."})
            return
        route = urlsplit(self.path).path
        if route not in {"/api/flow-check", "/api/simulation-records", "/api/verify-capture"}:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Page not found."})
            return
        if self.headers.get_content_type() != "application/json":
            self.send_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "Submit JSON flow measurements."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= 4096:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Provide a JSON body of up to 4 KB."})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            if route == "/api/verify-capture":
                if payload != {}:
                    raise ValueError("Verification uses the current server-side capture.")
                self.verify_capture()
                return
            if route == "/api/simulation-records":
                self.store_simulation(payload)
                return
            features = parse_features(payload)
        except (json.JSONDecodeError, UnicodeError, RecursionError):
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "The request body is not valid JSON."})
            return
        except ValueError as error:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return

        model_load = self.server.model_load
        if not model_load.done():
            self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Models are loading. Try again shortly."})
            return
        models = model_load.result()
        if models is None:
            self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Models could not be initialized. Check the backend log."})
            return
        if not models.lock.acquire(blocking=False):
            self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "A flow check is already running. Try again."})
            return
        try:
            results = models.check(features)
        except HaikuRequestError as error:
            self.send_json(HTTPStatus.BAD_GATEWAY, {"error": str(error)})
            return
        finally:
            models.lock.release()
        if not results:
            self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "No models returned a result. Check model status."})
            return
        self.send_json(HTTPStatus.OK, {"results": results})


    def verify_capture(self):
        haiku = getattr(self.server, "capture_ai", None)
        if haiku is None:
            self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "AI verification is unavailable on this console."})
            return
        snapshot = self.server.capture_feed.snapshot()
        intervals = snapshot["intervals"][-10:]
        packets = sum(interval["packets"] for interval in intervals)
        if snapshot["state"] != "live" or not packets:
            self.send_json(HTTPStatus.CONFLICT, {"error": "Wait for packets from the live collector."})
            return
        duration = sum(interval["elapsed"] for interval in intervals)
        byte_count = sum(interval["bytes"] for interval in intervals)
        measurements = {
            "window_seconds": round(duration, 2),
            "packet_count": packets,
            "byte_count": byte_count,
            "packets_per_second": round(packets / duration, 2),
        }
        if not haiku.lock.acquire(blocking=False):
            self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "An AI request is already running. Try again."})
            return
        try:
            reply = ask_claude(
                measurements, haiku.model, haiku.key, max_tokens=300,
                instruction=(
                    "Provide three short illustrative perspectives, each on its own line: "
                    "XGBoost-style (traffic volume and rate), Bi-LSTM-style (temporal behavior), "
                    "and Isolation Forest-style (deviation from normal). Use only these aggregate "
                    "measurements. State that timing patterns require a sequence and anomaly "
                    "judgments require a reference baseline. Do not invent attack labels, "
                    "scores, or security verdicts. Return plain text with the three labels."
                ),
            )
        except (OSError, HTTPException, ValueError, TypeError, KeyError):
            self.send_json(HTTPStatus.BAD_GATEWAY, {"error": "AI verification could not analyze this capture. Try again."})
            return
        finally:
            haiku.lock.release()
        self.send_json(HTTPStatus.OK, {"summary": reply["summary"], "measurements": measurements})

    def store_simulation(self, payload):
        storage = getattr(self.server, "simulation_storage", None)
        if not storage:
            self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "S3 storage is disabled."})
            return
        if not self.server.simulation_storage_lock.acquire(blocking=False):
            self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Another save is in progress. Try again."})
            return
        try:
            receipt = save_simulation(payload, *storage)
        except (AwsError, OSError, subprocess.TimeoutExpired):
            LOGGER.warning("Could not save or read back a simulation record in S3.")
            self.send_json(HTTPStatus.BAD_GATEWAY, {
                "error": "Could not confirm the S3 save. Check the AWS session and retry.",
            })
            return
        finally:
            self.server.simulation_storage_lock.release()
        self.send_json(HTTPStatus.OK, receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--database", type=Path, default=ROOT / "audit/spool/incident_store.db")
    parser.add_argument("--capture-stdin", action="store_true", help="Read packet metadata from the lab collector on stdin.")
    parser.add_argument("--haiku", action="store_true", help="Use Claude Haiku for simulated model assessments.")
    parser.add_argument("--simulation-bucket", help="Enable saving simulated traffic to this S3 bucket.")
    parser.add_argument("--aws-region", default=os.getenv("AWS_REGION", "ap-south-1"))
    parser.add_argument("--lab-container", help="Read live service status from this isolated Docker lab.")
    args = parser.parse_args()
    haiku = None
    if args.haiku:
        try:
            haiku = HaikuModels(os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5"), os.getenv("ANTHROPIC_API_KEY"))
        except ValueError as error:
            parser.error(str(error))
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), ConsoleHandler)
    except OSError as error:
        parser.exit(1, f"Unable to start the console on 127.0.0.1:{args.port}: {error}\n")
    with server:
        server.database = args.database
        server.simulation_storage = (args.simulation_bucket, args.aws_region) if args.simulation_bucket else None
        server.simulation_storage_lock = Lock()
        server.model_load = Future()
        server.capture_ai = haiku
        server.lab_checks = LabChecks(args.lab_container)
        server.capture_feed = CaptureFeed(configured=args.capture_stdin)
        try:
            print(f"SDN console available at http://127.0.0.1:{server.server_port}", flush=True)
            if haiku is not None:
                server.model_load.set_result(haiku)
            else:
                Thread(
                    target=load_release_models, args=(server.model_load,), name="model-loader", daemon=True
                ).start()
            if args.capture_stdin:
                Thread(target=server.capture_feed.read, args=(sys.stdin,), name="packet-reader", daemon=True).start()
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nSDN console stopped.", flush=True)


if __name__ == "__main__":
    main()
