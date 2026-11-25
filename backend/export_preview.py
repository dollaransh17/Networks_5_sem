"""Export a standalone console preview from sample data and the real polling engine."""

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from backend.models import ReleaseModels, parse_features
from backend.simulation import SCENARIOS, describe_scenario, run_scenario
from backend.store import BUCKET_COUNT, BUCKET_SECONDS, activity_window


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = {
    "packet_rate": 12,
    "byte_rate": 6480,
    "avg_packet_size": 540,
    "flow_duration_sec": 2.5,
    "packet_count": 30,
    "byte_count": 16200,
}


def sample_overview():
    samples = [
        ("sample-003", "192.0.2.18", "open", "2026-11-20T09:18:00Z"),
        ("sample-002", "192.0.2.24", "contained", "2026-11-20T09:04:00Z"),
        ("sample-001", "192.0.2.10", "closed", "2026-11-20T08:41:00Z"),
    ]
    as_of = int(datetime(2026, 11, 20, 9, 20, tzinfo=timezone.utc).timestamp())
    first = as_of - BUCKET_SECONDS * BUCKET_COUNT
    kinds = {
        "gateway": "gateway_deny",
        "suricata": "suricata_alert",
        "risk-policy": "decision_created",
        "sdn-controller": "rule_processed",
        "switch-counter": "effect_observed",
    }
    sample_minutes = {
        "gateway": (3, 8, 8, 14, 21, 21, 22, 35, 43, 43, 55),
        "suricata": (2, 12, 21, 21, 22, 37, 43, 43, 43, 51, 57, 57, 58),
        "risk-policy": (13, 22, 37, 43, 44, 51, 58),
        "sdn-controller": (44,),
        "switch-counter": (44,),
    }
    observations = []
    groups = Counter()
    for source, minutes in sample_minutes.items():
        for index, minute in enumerate(minutes):
            timestamp = first + minute * 60 + index
            groups[(minute * 60 // BUCKET_SECONDS, source)] += 1
            observations.append({
                "event_type": kinds[source], "source": source,
                "occurred_at": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
            })
    return {
        "audit_store": "ready",
        "counts": {"incidents": len(samples), "events": len(observations), "actions": 1},
        "incidents": [
            {"id": name, "subject_ip": address, "status": status, "opened_at": timestamp}
            for name, address, status, timestamp in samples
        ],
        "events": sorted(observations, key=lambda event: event["occurred_at"], reverse=True)[:8],
        "activity": activity_window(as_of, ((bucket, source, count) for (bucket, source), count in groups.items())),
    }


def export_preview(output):
    models = ReleaseModels(ROOT / "ai/models")
    results = models.check(parse_features(EXAMPLE))
    catalog = [describe_scenario(key, scenario) for key, scenario in SCENARIOS.items()]
    responses = {
        "/api/overview": sample_overview(),
        "/api/health": {"models_loading": False, "models": models.status},
        "/api/simulations": {"scenarios": catalog},
        **{f"/api/simulations/{key}": run_scenario(key) for key in SCENARIOS},
    }
    if results:
        responses["/api/flow-check"] = {"results": results}

    assets = ROOT / "frontend"
    html = (assets / "index.html").read_text(encoding="utf-8")
    css = (assets / "styles.css").read_text(encoding="utf-8")
    payload = json.dumps(responses, allow_nan=False).replace("<", "\\u003c")
    markup = html.replace('<link rel="icon" href="favicon.ico" sizes="32x32">', "")
    markup = markup.replace('<link rel="stylesheet" href="styles.css">', f"<style>{css}</style>")
    scripts = [f"<script>globalThis.sdnConsolePreview = {payload};</script>"]
    for name in ("traffic.js", "topology.js", "app.js", "live_lab.js"):
        markup = markup.replace(f'<script defer src="{name}"></script>', "")
        scripts.append(f"<script>{(assets / name).read_text(encoding='utf-8')}</script>")
    markup = markup.replace("</body>", "\n".join(scripts) + "\n</body>")
    output.write_text(markup, encoding="utf-8")
    return len(catalog), len(results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    simulations, models = export_preview(args.output)
    print(f"{args.output.resolve()} ({simulations} simulations, {models} recorded model predictions)")


if __name__ == "__main__":
    main()
