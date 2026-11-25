# FEATURES: MVP build guide

Build one feature at a time. After each, update PLAN.md checkboxes and wait for confirmation.

## F1: Access gateway policy
- **Does:** default deny, least privilege, rate limits. Story: Dev wants unauthorized traffic stopped early.
- **Screens:** Health and coverage. **Tables/API:** sensors, events; `POST /v1/events` (gateway_deny).
- **Order:** topology -> default deny -> allow list -> logging.
- **Edge:** IP is not identity; baseline before rate limits; internal OVS traffic may bypass the gateway.
- **Acceptance:** [ ] TCP 22 denied for ordinary device [ ] 443 allowed for authorized source [ ] denials logged [ ] denied traffic absent from OVS counters.

## F2: OVS telemetry and features
- **Does:** poll flow stats, compute rates. Story: Priya/Dev need valid measurements.
- **Tables/API:** events (samples), model features later.
- **Order:** poll -> store with timestamps -> diff -> validity checks.
- **Edge:** counter reset, rule replacement, switch restart, missing sample, subnet-wide rules give aggregate data only.
- **Acceptance:** [ ] rates use actual elapsed time [ ] reset detected [ ] PDF worked example reproduces.

## F3: Scoped enforcement and rollback
- **Does:** FLOW_MOD with cookie, priority, timeout; verification; rollback. Story: Dev wants self-fixing blocks.
- **Screens:** Active actions, confirm modal. **Tables/API:** actions, action_events; `POST /v1/actions`, `.../rollback`.
- **Order:** install -> barrier -> readback -> counter check -> expiry -> rollback.
- **Validation:** reject scope too broad; reject duplicate action_id; require expiry.
- **Acceptance:** [ ] rule has cookie and timeout [ ] "effect observed" only after real evidence [ ] rollback removes the exact rule [ ] retries create no duplicates.

## F4: Suricata inline + alert listener
- **Does:** inline drops; EVE events reach the risk engine. Story: Dev wants response without waiting for a poll.
- **Tables/API:** events; `POST /v1/events`.
- **Order:** inline test -> tail eve.json -> normalize -> validate -> dedupe -> submit.
- **Edge:** log rotation, malformed lines, NAT hiding subject, response packet containing the evidence, event storms.
- **Acceptance:** [ ] only alert events processed [ ] subject validated, not assumed [ ] duplicates suppressed [ ] alert, drop and OVS rule recorded separately.

## F5: Risk policy engine
- **Does:** chooses monitor / rate limit / DROP / quarantine / escalate. Story: operators want controlled decisions.
- **Tables/API:** policy_versions, actions, events.
- **Order:** decision table from PDF section 8 -> scope checks -> expiry -> escalation.
- **Edge:** ambiguous identity or critical service -> escalate; low-confidence anomaly -> monitor only.
- **Acceptance:** [ ] no broad block on shared IP [ ] every action has policy version and evidence refs.

## F6: Incident logger
- **Does:** correlated, append-only records with lifecycle. Story: Priya wants a trustworthy timeline.
- **Screens:** Incident list/detail. **Tables/API:** incidents, events, action_events; `GET /v1/incidents`.
- **Order:** initial event -> append outcomes -> durable spool -> stable IDs.
- **Edge:** disk full, clock drift, lost events (must be recorded as lost).
- **Acceptance:** [ ] never rewrites records [ ] unavailable model score stored as null [ ] queue bounds alert.

## States
Loading: skeleton rows. Empty: "No incidents". Error: standard error format with request_id.
