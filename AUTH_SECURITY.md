# AUTH_SECURITY: AI-Driven SDN Threat Isolation

The system is a lab backend with no public users, so "authentication" here means **service-to-service and operator access**. Email/password, OAuth, magic links and JWT refresh flows are not needed unless the V2 console adds human logins. Every choice is a proposal; the PDF leaves the mechanism open.

## 1. Authentication
- **Services:** mutual TLS (preferred) or per-service bearer tokens on a management-only network. One-line reason: the controller API must never be reachable from monitored traffic.
- **Operators/auditors (console):** SSO or username + strong password with MFA; short sessions. Reason: rollback and quarantine are powerful actions.
- **Flows:** login/logout/password reset only if the console is built; use a vetted identity provider rather than custom code.

## 2. Tokens
If bearer tokens are used: random 256-bit values, stored hashed, rotated on a schedule, scoped per role, never in code. If JWT is later added: access token 15 min, refresh token rotated on use, httpOnly secure cookie storage, reject expired/replayed requests.

## 3. Roles and permissions
| Action | listener | risk_engine | operator | auditor |
|---|---|---|---|---|
| Submit events | Yes | No | No | No |
| Create enforcement action | No | Yes | No | No |
| Roll back an action | No | No | Yes | No |
| Read incidents/actions | No | Yes | Yes | Yes |
| Seal evidence | No | Yes | Yes | No |
| Verify evidence | No | No | Yes | Yes |
| Change policy/thresholds | No | No | Yes (change-controlled) | No |
| Read signing/encryption keys | No | No | No | No |

## 4. Controller and response channel
Authenticate listener/risk/controller interfaces; restrict to the management network; authorize only approved action types; reject expired or replayed requests; deduplicate retries by `action_id`; never expose an unauthenticated controller API to monitored hosts. Log text is data, never a command.

## 5. Input validation
Validate every event: required fields, permitted sensor, IP/port ranges, string length caps, schema version. Reject `requested_action` from untrusted sources. Cap queue sizes. Treat Suricata/EVE content as untrusted (it can carry attacker-controlled strings).

## 6. Cryptography (as specified)
SHA-256 chain for linkage; ECDSA for signer binding; AES-256-GCM with a **unique nonce per key** and associated data; use vetted libraries only. Keys held in a separate protected store (key IDs in config, never key material). Record algorithm and key ID with each bundle. Call the trail **tamper-evident**, not tamper-proof. Anchor chain heads outside the writer.

## 7. Cloud
Least-privilege IAM per worker (write-only to the evidence bucket, no delete). S3 versioning + Object Lock: governance mode allows authorized bypass; compliance mode blocks deletion even by root during retention, so test in a disposable environment first. CloudWatch gets sanitized summaries only.

## 8. Data protection
Packet captures and payloads can contain credentials/PII: limit scope, retention, access. Redact sensitive fields before CloudWatch. Document what a lost event means for completeness.

## 9. Secrets and OWASP basics
No secrets in code or git; `.env` ignored; rotate on exposure; rate-limit internal APIs; return the standard error format without internals; dependency pinning and review.

## 10. Pre-launch checklist
- [ ] Management network isolated; controller API not reachable from lab traffic
- [ ] Service auth enabled; tokens/certs rotated
- [ ] Rollback tested by an operator
- [ ] Replay/expired requests rejected
- [ ] Keys outside repo; nonce uniqueness verified
- [ ] Object Lock mode chosen after a disposable test
- [ ] Evidence tamper test detected
- [ ] Fail-open/closed decision documented
- [ ] Experiments run only in the isolated, authorized lab
