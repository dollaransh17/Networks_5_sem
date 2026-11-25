# AGENTS.md: Rules for AI coding assistants

## Project summary
1. AI-driven SDN threat isolation in an isolated, authorized Mininet/OVS lab.
2. Stack: access gateway, inline Suricata, Open vSwitch, Ryu, risk policy engine.
3. Behaviour AI (XGBoost, Bi-LSTM, Isolation Forest) reads OVS counters via Ryu.
4. Ryu enforces only risk-approved, scoped, expiring OpenFlow actions.
5. A separate pipeline seals incident evidence (hash chain, ECDSA, AES-GCM) to S3.

## Source of truth (priority order)
1. docs/PRD.md  2. docs/DESIGN.md  3. docs/ARCHITECTURE.md  4. docs/DATABASE.md  5. docs/API.md

## DO
- Follow the folder structure in ARCHITECTURE.md.
- Reuse existing modules; keep functions small and commented where logic is subtle.
- Use actual elapsed time between counter samples, never a hard-coded interval.
- Give every enforcement rule a cookie, scope, priority and timeout.
- Record the full action lifecycle; "requested" is not "blocked".
- Keep event source labels: gateway denial, Suricata drop, OVS block are different.
- Handle errors, timeouts and queue limits explicitly; record lost coverage.
- Label every new idea "proposal" until it is implemented and measured.

## DO NOT
- Do not change the tech stack or add libraries without asking.
- Do not change the schema without updating DATABASE.md and API.md.
- Do not delete or rewrite working code unless asked.
- Do not hardcode secrets, keys, tokens or AWS credentials.
- Do not put AI inference or cloud calls inside Ryu's event-handling loop.
- Do not block on `src_ip` alone, and do not assume src_ip is the attacker.
- Do not invent metrics, latencies, accuracy or model scores. Use null.
- Do not repeat the "under 15 ms" claim as fact; it is unverified.
- Do not write attack tooling or run traffic outside the isolated lab.
- Do not rewrite sealed records; append a linked event.

## Workflow
1. **Plan:** state the change, files, and how you will verify it.
2. **Code:** smallest change that works.
3. **Summarize:** what changed, how verified, what remains unverified.

## Conflicts
If a request conflicts with any source-of-truth file, stop and ask before proceeding.
