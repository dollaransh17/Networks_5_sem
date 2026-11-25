"""Publish committed evidence bundles using the local AWS CLI profile."""

import argparse
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from contextlib import closing
from pathlib import Path


class AwsError(RuntimeError):
    pass


def aws(region, *arguments):
    result = subprocess.run(
        ["aws", "--region", region, "--no-cli-pager", "--output", "json", *arguments],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode:
        raise AwsError(result.stderr.strip())
    return json.loads(result.stdout or "{}")


def upload(region, bucket, key, path):
    try:
        result = aws(region, "s3api", "put-object", "--bucket", bucket, "--key", key,
                     "--body", str(path), "--checksum-algorithm", "SHA256",
                     "--if-none-match", "*", "--content-type", "application/json")
    except AwsError as error:
        if "(PreconditionFailed)" not in str(error) and "(412)" not in str(error):
            raise
        with tempfile.TemporaryDirectory() as directory:
            downloaded = Path(directory) / "existing.json"
            result = aws(region, "s3api", "get-object", "--bucket", bucket,
                         "--key", key, str(downloaded))
            if downloaded.read_bytes() != path.read_bytes():
                raise ValueError(f"Existing S3 object differs at {key}") from error
    version = result.get("VersionId")
    if not version or version == "null":
        raise ValueError(f"S3 object at {key} has no version ID")
    return version


def publish(args):
    with closing(sqlite3.connect(f"{args.database.resolve().as_uri()}?mode=ro", uri=True)) as audit:
        bundles = audit.execute(
            "SELECT id, sequence, record_hash FROM sealed_bundles ORDER BY sequence"
        ).fetchall()

    args.receipts.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(args.receipts, timeout=65)) as receipts:
        receipts.execute("""
            CREATE TABLE IF NOT EXISTS deliveries (
                bucket TEXT, object_key TEXT, version_id TEXT NOT NULL,
                log_destination TEXT, logged INTEGER NOT NULL,
                PRIMARY KEY (bucket, object_key, log_destination)
            )
        """)
        destination = f"{args.region}:{args.log_group}:{args.log_stream}"
        for bundle_id, sequence, record_hash in bundles:
            if not re.fullmatch(r"bnd-[a-f0-9]{12}", bundle_id):
                raise ValueError("Unexpected bundle identifier")
            key = f"evidence/{bundle_id}.json"
            identity = (args.bucket, key, destination)
            with receipts:
                receipts.execute("BEGIN IMMEDIATE")
                existing = receipts.execute(
                    "SELECT version_id, logged FROM deliveries "
                    "WHERE bucket=? AND object_key=? AND log_destination=?", identity
                ).fetchone()
                if existing and existing[1]:
                    continue
                if existing:
                    version = existing[0]
                else:
                    path = args.spool / f"bundle_{sequence:06d}_{bundle_id}.json"
                    bundle = json.loads(path.read_bytes())
                    if (bundle["bundle_id"], bundle["sequence"], bundle["record_hash"]) != (
                        bundle_id, sequence, record_hash
                    ):
                        raise ValueError(f"Spool file does not match committed bundle {bundle_id}")
                    version = upload(args.region, args.bucket, key, path)
                    receipts.execute(
                        "INSERT INTO deliveries VALUES (?, ?, ?, ?, 0)",
                        (args.bucket, key, version, destination),
                    )
            with receipts:
                receipts.execute("BEGIN IMMEDIATE")
                logged = receipts.execute(
                    "SELECT logged FROM deliveries WHERE bucket=? AND object_key=? AND log_destination=?",
                    identity,
                ).fetchone()[0]
                if logged:
                    continue
                message = json.dumps({
                    "event_id": f"{bundle_id}-evidence-stored",
                    "bundle_id": bundle_id, "outcome": "evidence_stored",
                })
                response = aws(
                    args.region, "logs", "put-log-events", "--log-group-name", args.log_group,
                    "--log-stream-name", args.log_stream, "--log-events",
                    json.dumps([{"timestamp": time.time_ns() // 1_000_000, "message": message}]),
                )
                if response.get("rejectedLogEventsInfo"):
                    raise AwsError("CloudWatch rejected the summary")
                receipts.execute(
                    "UPDATE deliveries SET logged=1 WHERE bucket=? AND object_key=? AND log_destination=?",
                    identity,
                )
            print(json.dumps({"bucket": args.bucket, "key": key, "version_id": version}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("audit/spool/incident_store.db"))
    parser.add_argument("--spool", type=Path, default=Path("audit/spool/sealed_bundles"))
    parser.add_argument("--receipts", type=Path, default=Path("audit/spool/aws-deliveries.db"))
    parser.add_argument("--bucket", default=os.getenv("EVIDENCE_BUCKET"), required=not os.getenv("EVIDENCE_BUCKET"))
    parser.add_argument("--region", default=os.getenv("AWS_REGION", "ap-south-1"))
    parser.add_argument("--log-group", default=os.getenv("CLOUDWATCH_LOG_GROUP", "/acn/lab/summaries"))
    parser.add_argument("--log-stream", default="local-lab")
    try:
        publish(parser.parse_args())
    except (AwsError, OSError, ValueError, KeyError, sqlite3.Error, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Publishing stopped. Run again to retry: {error}\n")


if __name__ == "__main__":
    main()
