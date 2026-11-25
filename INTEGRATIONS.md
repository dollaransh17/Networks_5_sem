# INTEGRATIONS: Third-party services

The PRD needs **no payments, no end-user email, no general file storage**, so those are excluded. Every integration sits behind a small service layer (`cloud/`, `sensors/`) so it can be swapped. Local protection never depends on any of them.

## Local components
| Component | Why | Wrapped by | Notes |
|---|---|---|---|
| Open vSwitch / Ryu | Enforcement and telemetry | `controller/ryu_app` | Only Ryu talks OpenFlow |
| Suricata | Inline IPS + EVE | `sensors/suricata`, `sensors/alert_listener` | Pin and test a supported release; choose fail mode |
| Wireshark/TShark | Validation captures | scripts in `experiments/` | Small controlled captures only |
| ClamAV (optional) | File-boundary scanning | future upload service | Not a network filter |

## AWS (V2/Later)
All AWS calls go through `cloud/` wrappers, **never** from Ryu's loop or from clients.
| Service | Why | Env | Setup (summary) |
|---|---|---|---|
| S3 Object Lock | Retain sealed evidence | `EVIDENCE_BUCKET`, `AWS_REGION` | Versioned bucket with Object Lock, deliberate retention mode; test in a disposable account |
| CloudWatch Logs | Summaries, metrics, alarms | `CLOUDWATCH_LOG_GROUP` | Publisher redacts sensitive fields first |
| SageMaker | Train/evaluate/register/approve models | `AWS_REGION`, model package group name | Approved version -> controlled local deploy -> rollback |
SDK: use the official AWS SDK for Python (`boto3`) *(assumption; confirm with the team)*. Credentials: IAM roles or a credentials provider, never in files.

## Behaviour of each integration
- **Retries:** exponential backoff with stable `event_id`/object keys so retries are idempotent.
- **Durability:** local spool queue; cloud outage -> keep spooling, record upload failures.
- **Webhooks:** none. CloudWatch alarm -> Lambda -> authenticated policy service is possible but is **not** the low-latency path to Ryu.
- **Cost/limits:** CloudWatch ingestion and S3 storage/retention grow with event volume (send summaries, not raw traffic); SageMaker costs only during training/hosting. Watch API throttling.
- **Fallback if down:** S3/CloudWatch down -> continue local response and spool; SageMaker down -> keep the current approved model version.
- **Testing:** use a disposable AWS account/bucket and short retention; local mocks (e.g., a stub uploader) for unit tests; never enable long compliance retention while testing.

## Wrapper contract (proposal)
`EvidenceStore.put(bundle) -> {bucket, key, version_id}`; `MonitoringSink.publish(summary)`; `ModelRegistry.latest_approved(name)`. Swapping providers changes only these classes.
