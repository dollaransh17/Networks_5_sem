"""Save aggregate simulation measurements and read the exact S3 version back."""

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote, urlencode
from uuid import UUID

from backend.models import parse_features
from cloud.publish import AwsError, aws, upload


LOGGER = logging.getLogger(__name__)


def save_simulation(payload, bucket, region):
    if not isinstance(payload, dict) or set(payload) != {"id", "destination", "measurements"}:
        raise ValueError("Provide a burst ID, destination, and flow measurements.")
    try:
        burst_id = str(UUID(payload["id"], version=4))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("The burst ID must be a UUID.") from None
    if burst_id != payload["id"] or payload["destination"] not in ("server", "quarantine"):
        raise ValueError("Invalid burst ID or destination.")
    measurements = parse_features(payload["measurements"]).features
    record = {
        "type": "simulated_traffic_burst",
        "id": burst_id,
        "destination": payload["destination"],
        "measurements": measurements,
    }
    key = f"evidence/simulations/{burst_id}.json"
    with TemporaryDirectory() as directory:
        path = Path(directory)
        original = path / "burst.json"
        original.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        version = upload(region, bucket, key, original)
        downloaded = path / "downloaded.json"
        aws(region, "s3api", "get-object", "--bucket", bucket, "--key", key,
            "--version-id", version, str(downloaded))
        stored = downloaded.read_text(encoding="utf-8")
        if stored.encode() != original.read_bytes():
            raise OSError("S3 readback differs from the uploaded burst.")
    logged = publish_simulation_summary(region, burst_id, key, record["destination"])
    options = urlencode({"region": region, "prefix": key, "versionId": version})
    return {"bucket": bucket, "key": key, "version_id": version, "json": stored, "cloudwatch_logged": logged,
            "console_url": f"https://s3.console.aws.amazon.com/s3/object/{quote(bucket, safe='')}?{options}"}


def publish_simulation_summary(region, burst_id, key, destination):
    message = json.dumps({
        "event_id": f"{burst_id}-simulation-stored",
        "simulation_id": burst_id,
        "outcome": "simulation_stored",
        "object_key": key,
        "destination": destination,
    })
    try:
        response = aws(
            region, "logs", "put-log-events",
            "--log-group-name", os.getenv("CLOUDWATCH_LOG_GROUP", "/acn/lab/summaries"),
            "--log-stream-name", os.getenv("CLOUDWATCH_LOG_STREAM", "local-lab"),
            "--log-events", json.dumps([{
                "timestamp": time.time_ns() // 1_000_000,
                "message": message,
            }]),
        )
        if response.get("rejectedLogEventsInfo"):
            raise AwsError("CloudWatch rejected the simulation summary.")
    except (AwsError, OSError, subprocess.TimeoutExpired, ValueError) as error:
        LOGGER.warning("CloudWatch summary failed for simulation %s: %s", burst_id, error)
        return False
    return True
