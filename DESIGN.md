# DESIGN: Operator Console Design System

**Scope note:** the architecture PDF defines no end-user UI beyond CloudWatch dashboards and alarms. This file is a *proposal* for a small operator/auditor console (or dashboard theme). It keeps the system explainable: every action shows who decided, why, scope, expiry and verified outcome. Do not invent colors or fonts outside this file.

## 1. Brand feel and principles
Precise, calm, evidence-first, like a flight-recorder viewer.
1. **Never overclaim:** distinguish *requested*, *accepted*, *observed*. Never show "blocked" for a queued request.
2. **Show provenance:** every record shows its source (gateway, Suricata, Ryu, model, policy).
3. **Reversible by default:** actions show expiry and a rollback control.

## 2. Color palette (HEX)
| Role | Light | Dark |
|---|---|---|
| Primary | #1F4E8C | #8DB7F0 |
| Secondary | #4A5568 | #A0AEC0 |
| Background | #FFFFFF | #0F1318 |
| Surface | #F3F5F8 | #1A2029 |
| Text | #1A202C | #E8ECF2 |
| Success | #1E7A46 | #5FD08E |
| Warning | #9A5B00 | #F2B84B |
| Error | #B3261E | #FF8F86 |

Status mapping: pending_verification = Warning; data_plane_effect_observed = Success; failed/rejected = Error; expired/reverted = Secondary. Always pair color with a text label.

## 3. Typography
System UI stack for text; `ui-monospace, Menlo, Consolas, monospace` for IPs, IDs, hashes. Sizes (px): 12, 14, 16, 20, 24, 32. Weights 400/500/600. Line heights 1.5 body, 1.3 headings, 1.4 mono.

## 4. Spacing, radius, shadows, breakpoints
Spacing 4/8/12/16/24/32/48. Radius 4 inputs, 8 cards/buttons, 12 modals. Shadows sm `0 1px 2px rgba(0,0,0,.08)`, md `0 4px 12px rgba(0,0,0,.12)`. Breakpoints 768 / 1024 / 1440 (console is desktop-first).

## 5. Components (states)
| Component | Default | Hover | Focus | Disabled | Loading | Error |
|---|---|---|---|---|---|---|
| Button (primary) | Primary bg | darker 8% | 2px outline + offset | 40% opacity | spinner + label | n/a |
| Destructive button (Rollback, Quarantine) | Error bg | darker | outline | 40% opacity | spinner | inline message |
| Input / filter | 1px border | border darker | 2px Primary outline | muted | n/a | Error border + text |
| Card (incident summary) | Surface | shadow sm | outline if clickable | n/a | skeleton | Error border |
| Modal (confirm rollback) | Surface, shows scope + expiry | n/a | focus trapped | n/a | spinner on confirm | inline error |
| Navbar | Background | underline | outline | n/a | n/a | n/a |
| Table (events) | dividers | row tint | row outline | n/a | skeleton rows | empty/error row |
| Toast | Surface | pause timer | outline on dismiss | n/a | n/a | Error bar |

Every destructive action requires a confirm modal listing switch, match, scope, expiry.

## 6. Screens (from PRD)
1. **Incident list:** filter by status/severity/time; columns: incident ID, subject IP, decision, status, created.
2. **Incident detail:** lifecycle timeline (decision_created ... expired/reverted) with timestamps and source labels; evidence references; model scores (or "unavailable"; never a fabricated score).
3. **Active actions:** rule cookie, switch, match, expiry countdown, rollback button.
4. **Health and coverage:** Suricata, Ryu, AI service, spool depth, lost-event count, degraded-protection time.
5. **Evidence verification:** result of decrypt, signature, hash-chain checks; broken-link or missing-record warnings.
6. **Experiment run view (research):** latency measures and environment versions per run.

## 7. Accessibility
Contrast >= 4.5:1 text, 3:1 large text/borders (verify with a checker); visible focus rings; full keyboard operation, Esc closes modals with focus trap; status never by color alone; `aria-live="polite"` for status changes; respect `prefers-reduced-motion` and `prefers-color-scheme`.
