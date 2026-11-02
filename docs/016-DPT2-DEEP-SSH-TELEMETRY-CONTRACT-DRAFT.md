# DPT/2 — draft transport contract for authenticated SSH measurements
**Status: DRAFT, documentation + machine fixtures only, 2026-11-02. Not implemented, deployed, accepted or permitted for live devices yet.**
**Rationale:** Immutable DPT/1 has no independent TCP preflight or authenticated SSH/data-plane measurements. A breaking major version avoids misinterpreting old s=1 `SERVICE_ACCEPT_PASS` as NPV healthy.

## Artifact inventory
- `contracts/dpt/v2/code-registry.json` — proposed numeric wire codes (never C++ enum position).
- `contracts/dpt/v2/telemetry.schema.json` — JSON Schema 2020-12 structural checks.
- `contracts/dpt/v2/ack.schema.json` — ACK schema.
- `contracts/dpt/v2/fixtures.json` — synthetic D0, D1 and healthy examples, invalid boundary examples.
- `contracts/dpt/v2/hmac-test-vectors.json` — synthetic cross-language MAC golden input.

## Compatibility / routing
- DPT/1 remains immutable and accepted at `POST /api/dpt/v1/telemetry`; v1 status means **pre-auth SSH only**, even after rollout.
- New DPT/2 uses **HTTPS only** `POST /api/dpt/v2/telemetry`, raw body maximum **1024 bytes**, one event per request, no batches, no redirects, normal hostname+CA verification. Keep ACK codes 0 ACCEPTED, 1 DUPLICATE, 2 HISTORY_ONLY, with `v=2`.
- Authenticated HMAC SHA256 per-device with new, independent key ID/secret domain. Signed ASCII payload consists of 7 LF-separated fields with no trailing newline: `DPT2\nPOST\n/api/dpt/v2/telemetry\n<device_id>\n<key_id>\n<sent_uptime_decimal>\n<sha256_hex_of_exact_raw_body>`. Signature base64url without padding; headers remain `X-DPT-Device`, `X-DPT-Key-Id`, `X-DPT-Sent-Uptime-Ms`, `X-DPT-Signature`. Canonical decimal and exact raw bytes; no silent v1->v2 key reuse, no secrets in telemetry.
- Boot b + q event uniqueness, immutable retried body and signed fresh sent uptime, FIFO, latest-state freshness, idempotent ACK, history_only and gap policy carry forward. Unknown codes are stored safely and NOT classified. `k=3 BOOT` first q=1. No relabeling lost q.
- Correlate a device's `t` to target hostname+port and **server-owned revision**; never embed actual relay IP, credentials, user identity or cause-of-filtering claim in payload.

## Root fields (from DPT/1, unchanged meaning)
`v=2,id,b,q,u,k,t,w,r,s,p,o,d,x,a,ts,h`. The legacy `s`/ `p` / `o` still mean ONLY pre-auth SSH transport/host key/service accept. Existing `h` means a newly measured **direct hotspot HTTPS** control, not tunneled HTTPS. Omit `h` if no new measurement.
New fields are `c` (independent TCP preflight) and `z` (authenticated SSH/session/data-plane). Both optional; **absent means NOT MEASURED** (never success or failure). They may appear only on `k=1 PROBE_RESULT`. `z` requires root `s=1` (`SERVICE_ACCEPT_PASS`). `c` may be present even when root SSH fails.

### `c` — independent TCP preflight
`{"u":<completion_uptime_ms>,"s":<tcp_code>,"ms":<elapsed_ms_if_measured>}`.
Codes: 1 PASS; 20 CONNECT_TIMEOUT; 21 CONNECT_REFUSED; 22 NETWORK_ERROR; 90 LOCAL_UNMEASURABLE. No claim about who dropped packets; TCP timeout can equally reflect server/firewall/routing impairment. Do not infer preflight failure from `ssh_connect()` alone.

### `z` — authenticated SSH, restricted test identity only
`{"u":<completion_uptime_ms>,"s":<terminal_deep_code>,"am":<auth_duration_ms_optional>,"sm":<post_auth_session_elapsed_ms_optional>,"f":<sample1_optional>,"g":<sample2_optional>}`.
`z.s`: 1 COMPLETE, 10 AUTH_REJECTED, 11 AUTH_TIMEOUT, 12 AUTH_ERROR, 20 SESSION_RESET, 21 SESSION_TIMEOUT, 30 CHANNEL_OPEN_FAILED, 31 CHANNEL_OPEN_TIMEOUT, 40 DATA_TIMEOUT, 41 DATA_INCOMPLETE, 42 DATA_SLOW_SUSPECT, 90 LOCAL_UNMEASURABLE.
Each attempted transfer `f` and `g`:
`{"s":<transfer_code>,"r":<requested_bytes>,"n":<received_bytes_if_measured>,"ms":<transfer_elapsed_ms_if_measured>}`.
Transfer codes: 1 COMPLETE; 2 SLOW_SUSPECT; 20 TIMEOUT; 21 IO_ERROR; 22 INCOMPLETE; 23 CHANNEL_ERROR; 90 UNMEASURABLE. Allowed requested bytes 1..65536; 0 <= received <= requested. `s=1|2` MUST include `n=r` and measured `ms`. A missing `g` is NOT second-sample failure unless the terminal `z.s` and channel evidence support it. `z.s=1` requires `f` and `g` full/complete codes; `z.s=42` requires at least one full `SLOW_SUSPECT` sample. `z.s=10|11|12` forbids data samples. Never send passwords, SSH keys, payload data or a censorship verdict.

## Time, age and gaps
`u` and nested `c.u`, `z.u`, `h.u` are unsigned extended boot-relative uptime at **their own completion** (64-bit bounded by JS safe integer); `X-DPT-Sent-Uptime-Ms >= max(all present completion uptimes)`. A TCP preflight may complete before root `u`; authenticated second transfer and direct HTTPS may complete after root `u`. Backend retains signed sender-age and receipt time; cannot invent exact wall clock on ESP32 without validated `ts`. Late/out-of-order events are historical only. Terminal failures after a completed session must be distinguished from unavailable local SOCKS listeners, which are **not ESP32 observations**.

## Classifier is a separate server-owned policy (NOT wire data)
- D0 `TCP_UNREACHABLE`: repeated eligible `c.s=20|21|22` (may be server fault); require recent independent control and server-health corroboration for stronger filtering suspicion.
- D1 `SESSION_FAILURE`: `c.s=1`, pre-auth pass, `z.s=20|21|30|31` or an incomplete second sample after verified first full, excluding local errors.
- D2 `DATA_DEGRADED`: failed/partial or significantly slow authenticated transfer under a calibrated, size-specific baseline; never use raw speed inferred from direct `h`.
- HEALTHY requires recent success at every **enabled** level; old DPT/1 or pre-auth PASS cannot be FULL_HEALTHY.
- MONITORING_UNKNOWN on Wi-Fi drop, stale data, host-key mismatch, local resource, collector gap, unknown wire code or unavailable control. RECOVERED only after corroborated fresh passes.
Filtering suspicion `INCONCLUSIVE/SUSPECTED/HIGH_CONFIDENCE` is a server interpretation with reason codes, not a wire field. No fixed percent probability without calibrated statistical model. Thresholds, transfer-size/cadence and HTTP timing SLO are pilot settings, not normative fields.

## Invariants / negative conformance tests to implement before activation
JSON Schema alone is insufficient; Collector MUST validate: HMAC and key version, no duplicate keys, k-kind restrictions, `z` only with `s=1`, timing bounds and monotonic age, transfer n <= r, full status implies n==r, terminal deep/status sample relationships, HTTPS freshness, unknown codes not actionable, valid registered target/revision, boot+sequence ordering and ACK matching. Add tests for D0 with missing z, first successful then second timed-out/connection reset, complete two-sample healthy, missing g, Wi-Fi down, stale h, payload-size >1024, altered signed input, bad host key, old DPT/1 coexistence and double-delivery.
Reference implementation MUST match `hmac-test-vectors.json` exactly before accepting any DPT/2 request.

**Security/release:** this is a draft contract for the approved roadmap, not an authorization to enable live SSH authentication or change NVLBot production. No firmware/collector/bot source edited by this documentation PR.
