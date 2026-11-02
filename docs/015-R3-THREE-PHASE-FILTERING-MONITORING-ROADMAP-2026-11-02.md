# DenaProbe R3 — approved three-phase delivery roadmap
**Approved:** 2026-11-02 | **Status:** design and contract only; NO implementation, production enablement, deployment, or bot activation in this change.
**Repositories:** `DenaSon/DenaProbe` (ESP32 firmware + versioned protocol) and `DenaSon/nvl-bot` (independent Collector, detector, admin Telegram bot).
**Canonical deep telemetry draft:** [016 / DPT/2](016-DPT2-DEEP-SSH-TELEMETRY-CONTRACT-DRAFT.md).

## Final objective
Send trustworthy time-stamped ESP32 measurements to Core; derive a **probabilistic filtering-suspicion assessment** and explicit observed failure class **on Core**; alert authorized administrators via **Telegram Bot API 10.3 Rich Messages** and send one recovery notice. The device NEVER labels observations as proven censorship, and no single ISP hotspot proves who caused failure. Device vantage is ESP32 -> phone Wi-Fi hotspot -> selected operator; its Wi-Fi RSSI is NOT LTE RSSI. A genuine NPV client remains an independent reference, never inferred from a probe.

## Evidence frozen (not implementation claims)
- Healthy SSH SOCKS data transfer: RighTel and MCI on 153.75.85.50:2252, **9/9 completed** each; healthy during respective measurement windows.
- 2026-11-02 MCI / same 153.75.85.50:2252: authenticated SSH transferred the first 64KiB sample, then another request timed out and the SSH process ended with `Connection reset` (observed process duration ~42.7s). Direct HTTPS completed 9/9. This is **D1**, transport/session after initial success, not proof of DPI or origin of RST.
- 2026-11-02 MCI / 153.75.89.31:2252: 10/10 **TCP connect timeout**, pre-auth SSH never started, direct HTTPS completed 9/9. This is **D0**.
- On a previous .250 incident, SOCKS retries after SSH process exit were not active SSH data-plane failures. Never classify absent local SOCKS listeners as network data-plane throttling.
- D2 (complete but severely slow, or partial/timeout in authenticated data transfer) needs calibrated hardware field evidence before an actionable threshold.
- Tests involving **different relay IPs** cannot establish a causal carrier-only comparison.

## Baseline / existing code review (2026-11-02)
- `master` default `esp32dev` remains v0.0.4 passive SSH banner firmware; experimental `esp32dev_ssh_feasibility` has SSH transport + SHA256 pinned host key + SERVICE_ACCEPT and independent public HTTPS, **no SSH user-auth or tunneled payload**.
- DPT/1 firmware sender and isolated Python/SQLite Collector are on unmerged R2-A/R2-B branches; signed field delivery passed. R2-C FIFO/continuity fixes exist on open stacked PRs **DenaProbe #7** and **nvl-bot #263**; merge/deploy/field acceptance not verified. Do not infer actual running binaries from branch code.
- Existing DPT/1 contract is immutable. Add `contracts/dpt/v2/*` draft; maintain DPT/1 compatibility. No unreviewed in-place reinterpretation.

## Phase 1 — reliable evidence transport and live state (R2-C closeout)
**Board:** review and land FIFO sequence-preserving sender, immutable retries, matching ACK, bounded queue and overflow gap, device reboot/boot ID, TLS verification, HMAC key hygiene. The sensing loop must not block on upload.
**Core:** review/land ordered-ingest + two *consecutive eligible fresh SSH probes* before clearing monitoring_gap; stale/out-of-order/history-only data must never advance live status. Separate latest SSH vs HTTPS freshness. Verify key `k1` revocation by key ID only, preserve active `k2`; never display secrets.
**Gate:** confirmed ordered q progression and newer HTTPS sequence live; correct delayed delivery, history, reboot, invalid HMAC, 429/5xx, queue overflow and offline recovery; no false failure/recovery from delivery gaps; physical ESP32 + staging Core acceptance. No detector or alert enabled until gate passed.
**Files:** `src/denaprobe/TelemetryCodec.h`, `TelemetryTransport.h`, independent `denaprobe_ingest/collector.py`.

## Phase 2 — complete D0/D1/D2 measurements + DPT/2
**Board:** retain existing pre-auth SSH and direct public HTTPS; add independent bounded TCP connect (separate from `ssh_connect()`) to distinguish D0, with observed DNS/connect times and locally unavailable code. Add **isolated, opt-in Feasibility Spike** for authenticated SSH under a **dedicated restricted non-customer monitoring identity** with independently provisioned credential, verified host-key pin, strict timeouts, small memory ceiling. Open one restricted `direct-tcpip` channel and collect two controlled, checksum/length-verifiable bounded payload samples on a single fresh session, separated by a short dwell interval. Record auth outcome, session lifetime, channel outcome, first/second sample sizes/durations and a reset/timeout code; stop cleanly on deadline. First/second sample requested sizes are explicitly recorded (up to 64KiB); **cadence and bytes are pilot-configurable and must pass LTE data-budget and <90s warning feasibility review**. Never use production user passwords, root access, customer traffic or automatic reconnect loops. No concurrent SSH/HTTPS/telemetry workers; preserve heap thresholds, watchdog and LED safety.
**Core:** add versioned DPT/2 acceptance on a **separate signed /api/dpt/v2/telemetry endpoint**, preserving v1 endpoint/storage interpretation. Validate nested TCP and authenticated data-plane fields, signed raw bytes, enum semantics, age bounds and payload 1024-byte ceiling. Persist request version, target revision, data-plane evidence, source/receive/measurement times and history. Old v1 samples remain **pre-auth-only**: never reinterpret them as VPN/NPV working.
**Edge provisioning:** read-only/least privilege; separate service account with public-key auth, no interactive shell, forwarding restricted to a known controlled responder; capture relay's own sshd health independently when practical. No changes to customer NPV accounts.
**Gate:** reproduce D0 (TCP timeout) and D1 (first pass then session/channel reset) via deterministic fixtures + real ESP32; D2 tested against calibrated transfer error/slow references; pinned key invalid => SECURITY/UNKNOWN, hotspot down => LOCAL/UNKNOWN; memory/watchdog and resource/data-budget stable; no soft false HEALTHY on SERVICE_ACCEPT alone. **If ESP32 authenticated data plane is infeasible**, report that gate as blocked; do not label it complete or silently substitute direct HTTPS.

## Phase 3 — server classifier + Telegram Rich Message dashboard
**Core:** separate read-only detection worker consuming accepted fresh measurement history, not raw unverified network calls. Produce D0 TCP_UNREACHABLE, D1 AUTH_SESSION_RESET_OR_CHANNEL_FAILURE, D2 DATA_PLANE_DEGRADED, HEALTHY, MONITORING_UNKNOWN, RECOVERED. Require consecutive valid measurements, independent HTTPS control freshness, target-revision consistency and deduped incident state machine. Isolate local Wi-Fi loss, stale telemetry, resource/host-key failures and collector outages as UNKNOWN / monitoring problem, **not filtering**. Filtering suspicion: NONE / SUSPECTED / HIGH_CONFIDENCE / INCONCLUSIVE, with evidence and uncertainty; HIGH needs corroboration beyond one ESP32 vantage (e.g., independent server health/another operator). No fabricated percentage.
**Bot:** Telegram Bot API 10.3 **Rich Message** admin dashboard as mandatory presentation: compact Persian cards/table-like rows showing currently monitored operator+target, active incidents, evidence, confidence, last fresh sample, probe age and recovery; inline controls for incident details / history / refresh; contextual footer tips, short copy, status colors, clear PENDING/UNKNOWN. Authorization restricted to registered admin roles. Notification on incident onset/escalation and recovery, idempotent deduplication and cooldown; never send individual per-probe spam. **No Mini App, no HTML fallback dashboard, no auto-switch / network mutation.**
**Gate:** end-to-end recorded healthy, D0, D1, D2, Wi-Fi-off, stale/collector-down and recovery cases; false-positive review; bot authorization, rendering on iOS/Android Telegram, deduplication and recovery tests. Production notifications explicitly gated by operator signoff.

## Notification performance target (not a guarantee)
An initial **<=90-second** alert target applies only when real sampling cadence, deep-session dwell, collection delivery and server evaluation support it. Fast D0 may use 30s pre-auth checks; D1/D2 cannot have a 90s guarantee if authenticated deep checks are scheduled less often than that. Measure end-to-end `incident_started_at`, `measurement_completed_at`, `received_at`, `classified_at`, `notified_at` before claiming an SLA. If data is missing, issue MONITORING_UNKNOWN instead of an invented outage. Never infer carrier identity from Wi-Fi SSID alone.

## Explicit exclusions
No SIM800L or additional modem; no dashboard outside existing NVLBot; no changes to production NPV/GOST/DNS/relays; no administrative relay-switch event logging; no remote actions from board; no automatic switching; no forced port/route change; no automatic firmware deployment. Historical cases are not proof of the cause. All cross-repo merges and live rollout must be separately approved.

## Work order
1. Close R2-C, verify physical sender/Collector state.
2. Implement DPT/2 parser and device measurement **in staging**, with cross-language fixtures and compatibility tests; then pilot authenticated probing on ESP32.
3. Implement detector and **Rich Message** NVLBot UI/alerts; require end-to-end acceptance and human activation.
