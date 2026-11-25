"""Check Claude against observed ICMP traffic between the lab sensor and protected server."""

import argparse
from http.client import HTTPConnection, HTTPSConnection, HTTPException
import json
import os
from time import monotonic, sleep, time


SENSOR = "10.0.2.1"
SERVER = "198.51.100.20"


def read_capture(port):
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", "/api/packets")
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"Capture endpoint returned HTTP {response.status}. Check the console version and port.")
        return json.load(response)
    finally:
        connection.close()


def observe_exchange(port):
    started = time()
    deadline = monotonic() + 30
    print("Waiting for the lab probe. In Mininet run: ips ping -c 3 198.51.100.20", flush=True)
    while monotonic() < deadline:
        capture = read_capture(port)
        state = capture["state"]
        if state in {"disabled", "stopped"}:
            raise ValueError(f"Collector is {state}. Start the console with the lab packet collector.")
        if state == "live":
            if capture["interface"] not in {"s1-eth1", "s1-eth2"}:
                raise ValueError("Select s1-eth1 or s1-eth2 to observe the protected-server path.")
            # Each snapshot contains retained headers. Count one snapshot so polling
            # the same report more than once cannot inflate the evidence.
            counts = {"to_server": 0, "from_server": 0}
            octets = {"to_server": 0, "from_server": 0}
            for row in capture["rows"]:
                if row["at"] < started or row["protocol"] != "ICMP":
                    continue
                pair = (row["source"], row["destination"])
                if pair == (SENSOR, SERVER):
                    direction = "to_server"
                elif pair == (SERVER, SENSOR):
                    direction = "from_server"
                else:
                    continue
                counts[direction] += 1
                octets[direction] += row["bytes"]
            if min(counts.values()) >= 3:
                return {"protocol": "ICMP", "observed_packets": counts, "observed_wire_bytes": octets}
        sleep(0.5)
    raise ValueError("Timed out waiting for three fresh ICMP headers in each direction on the protected-server path.")


def ask_claude(measurements, model, key, *, instruction=None, max_tokens=120):
    if not key or not key.isascii() or any(not c.isprintable() or c.isspace() for c in key):
        # Keep invalid header values out of http.client's error messages.
        raise ValueError("ANTHROPIC_API_KEY contains an empty value or invalid characters.")
    connection = HTTPSConnection("api.anthropic.com", timeout=20)
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": (
            (instruction or (
            "Summarize these observed counts for a controlled lab connectivity probe in one sentence. "
            "The capture contains sampled packet headers. Avoid inferring packet loss or security status. "
            )) + "\n" + json.dumps(measurements)
        )}],
    }
    try:
        connection.request("POST", "/v1/messages", body=json.dumps(body).encode(), headers={
            "Content-Type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": key,
        })
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"Anthropic returned HTTP {response.status} (request ID {response.getheader('request-id')}).")
        result = json.load(response)
        summary = " ".join(block["text"] for block in result["content"] if block.get("type") == "text").strip()
        if not summary:
            raise ValueError("Anthropic returned a message without a text summary.")
        return {"model": result["model"], "message_id": result["id"], "summary": summary}
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5174, help="Loopback console port")
    args = parser.parse_args()
    key = os.environ.get("ANTHROPIC_API_KEY")
    model = os.environ.get("ANTHROPIC_MODEL")
    if not key or not model:
        parser.exit(1, "Load ANTHROPIC_API_KEY and ANTHROPIC_MODEL from the project .env.\n")
    try:
        measurements = observe_exchange(args.port)
    except (OSError, HTTPException, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Capture check failed: {error}\n")
    print(json.dumps(measurements), flush=True)
    try:
        reply = ask_claude(measurements, model, key)
    except (OSError, HTTPException, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Claude check failed: {error}\n")
    print(json.dumps(reply))


if __name__ == "__main__":
    main()
