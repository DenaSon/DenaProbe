# R2-A — DPT/1 ESP32 Sender (firmware only)

**Branch:** `feature/r2a-dpt1-telemetry-sender-20261031` · **Date:** 2026-10-31  
**Status:** implement/test as experimental only; backend R2-B and end-to-end R2-C are **not deployed**. No filtering determination or notification on ESP32.

## What R2-A adds

- Uses the already-existing, independent SSH (~30 s) and HTTPS (~180 s)
  observations without changing their probes, pinned SSH host key, trusted
  HTTPS endpoint, or meaning.
- Builds DPT/1 **immutable** one-event-per-POST payloads from numeric
  status/stage/observation codes, DNS/transport/service durations and **new**
  HTTPS samples. Source Serial output remains separate diagnostic metadata;
  it is never sent as opaque text.
- Crypto-strength **128-bit random boot ID**, per-boot event sequence spanning
  `BOOT`, `PROBE_RESULT`, `DEVICE_EVENT`, extended 64-bit uptime and optional
  Wi-Fi link events. Identifiers are opaque; backend owns target mapping.
- A bounded **12-message RAM queue** (~12.5 KiB static bytes), no per-sample
  flash writes. BOOT stays queued until collector ACK. On overflow, evict
  an older non-BOOT message; count/report dropped records and leave a numeric
  sequence gap for the backend. Do not assume lost samples were SSH failures.
- Sending cadence: **normal flush opens at ~90s**, then drains queued records
  one by one; BOOT, failed SSH and local fault results can send as soon as
  internet/clock/resource conditions allow. One POST always contains
  **one** DPT/1 event, not a JSON batch.
- Prioritizes recently measured data when the queue contains backlog;
  older accepted data is expected to be marked `HISTORY_ONLY` by the server.
  Receipt time and `send_uptime-u` distinguish delivery delay; older records
  must not trigger new incidents.
- HTTPS delivery with a locally provisioned CA + **hostname verification**,
  SHA-256 body hash, HMAC-SHA256 over the DPT1 canonical signing string,
  unpadded base64url signature, matching `v,b,q` durable ACK.
  Reject redirects and malformed/ambiguous/changed ACK identity.
- Bounded retry for temporary network/429/5xx failures with exponential
  backoff + jitter, security/config stop on 401/403/409/413 or malformed
  ACK, and explicit gap reporting if a retry budget expires. Sender stops
  retrying one structurally rejected 400/422 event and counts loss.
- Sender is an isolated FreeRTOS worker with **no TLS overlap** against the
  already memory-heavy SSH/HTTPS probe worker. Probe measurement remains
  independent of collector reachability. Serial reports sender queue/gaps,
  no secrets, no incident verdict.

## Safety and configuration

Default build remains **disabled** (`PROBE_DPT_ENABLED=0`) and runs existing
R1 probing unchanged. The sender is not configured by the example file:
`include/telemetry_private.h.example` is only a guide. Copy it to
**ignored** `include/telemetry_private.h` when the Core collector actually
exists, provision a **distinct random 256-bit HMAC key per board** and a
verified, current CA PEM. Set `PROBE_DPT_ENABLED=1` only then.

`PROBE_DPT_API_URL` must be an HTTPS **DNS hostname** at the exact
`/api/dpt/v1/telemetry` path; no redirects, URL tokens or credentials.
Prefer an isolated TLS API/edge rather than exposing the protected Core SSH
host or coupling upload availability to the NPV relay being tested.

A missing or invalid DPT configuration disables only the sender;
measurement continues. If SNTP is not ready, the sender queues data and
**does not** disable TLS certificate checks. Memory-held events are lost
on ESP32 reset (registered new BOOT identity). While the same cellular
internet is genuinely down, buffered events cannot reach the Core; the
backend must use `DEVICE_STALE/MONITORING_GAP` rather than asserting an ISP
outage from silence.

**Important staging limitation:** R2-A is a **source-only sender**.
Do not claim ingestion, durable storage, customer VPN testing, filtering
identification, real-time sub-minute alerting, or successful hardware upload
until R2-B and R2-C complete.

## Design of per-cycle HTTPS pairing

R1 emits SSH_RESULT before HTTPS_RESULT on the same worker. DPT/1 allows
`h` **only if that exact SSH cycle runs a new HTTPS sample**. The sender
therefore temporarily holds that SSH result until its HTTPS_RESULT arrives,
then encodes **one immutable PROBE_RESULT** with `u` (SSH completion uptime)
and `h.u` (HTTPS completion uptime). A cycle without HTTPS is encoded and
queued immediately. A cached HTTPS from `[probe-overall]` is NEVER sent as
a new `h`. The time spent on this actual HTTPS measurement is not a
network send delay; backend must use send-uptime and measurement ages.

## Server checklist (R2-B)

- Validate HMAC against the original exact body bytes, approved device/key
  identity and signed per-send uptime; never trust C++ enum ordinals.
- Persist uniquely on `(device_id, boot_id, sequence)` including body hash.
  Same bytes => `DUPLICATE`; changed bytes => `409`. Reject/restrict
  replayed BOOT and out-of-order live-state promotions.
- Send HTTP 200 **only after durable DB commit** and include a bounded JSON
  ACK `{"v":1,"b":"<boot>","q":<seq>,"ack":{"r":0|1|2}}`
  with `Content-Length` and no extra schema fields.
- Ingestion acknowledges historical-only delayed events but **must not**
  promote them into live-alert candidates or claim VPN/failover.
- Register each Edge/relay destination with versioned target identity,
  distinct from the protected Core infrastructure identity.

## Verification and limitations

Run local host regressions via `python tests/run_host_tests.py`.
CI must build both `esp32dev` and `esp32dev_ssh_feasibility`.
Existing SSH/HTTPS hardware tests should still pass without DPT config.

R2-C must confirm the following with an actual authenticated Core test
collector: HMAC golden vector, correct JSON/schema and stage bits, TLS CA
and SNI, ACK/duplicate/altered-body handling, 90s normal flush, urgent
failure, queue overflow under outage, 429/5xx/reboot behavior, no overlap
or heap crashes during 24h operation, and accurate `HISTORY_ONLY`
classification. Excluding the Core collector from this PR is deliberate.

The definition of operational filtering is **not** a wire status and is
never computed on ESP32. SSH pre-auth PASS and public direct HTTPS PASS
do not prove the NPV application data path is healthy.

## Offline hardware smoke test — FIRST, before Core setup

**Test source branch:** `feature/r2a-dpt1-telemetry-sender-20261031`.
Keep the existing private `include/probe_private.h` with the actual
SSH Edge hostname and independently verified host-key pin. Do **not**
overwrite or commit that file.

1. Copy `include/telemetry_private.h.example` to
   `include/telemetry_private.h` (ignored by Git).
2. Set `PROBE_DPT_ENABLED=0` and `PROBE_DPT_OFFLINE_SMOKE_TEST=1`.
   Leave the device secret, URL and CA empty/placeholders for now.
3. `python tests/run_host_tests.py`
4. `pio run -e esp32dev_ssh_feasibility`
5. `pio run -e esp32dev_ssh_feasibility -t upload`
6. `pio device monitor -b 115200 -f time -f log2file`
7. Check `[dpt] READY | ... mode=OFFLINE_SMOKE_NO_NETWORK`,
   `[dpt-smoke] WOULD_SEND_NOT_DELIVERED` and valid `json=` payloads:
   first event `k=3,q=1`; SSH results have `k=1,s,p,o,d,x,a`
   as measured; HTTPS subobject `h` appears **only with a fresh
   HTTPS_RESULT**. A successful SSH+HTTPS cycle must not create two
   DPT/1 result messages. See `[quality-sample]` for timing cross-check.
8. Keep Wi-Fi / LED / SSH / HTTPS behavior intact and verify no unexpected
   watchdog, heap exhaustion or boot loop in a prolonged observation window.
9. **Record the serial output and firmware commit** for review before any
   Core networking. No real packet is delivered, no HMAC or TLS exchange
   occurs, and the printed/simulated removal is **NOT** durable ACK.
10. Switch `PROBE_DPT_OFFLINE_SMOKE_TEST` back to `0` after testing.
    Leave `PROBE_DPT_ENABLED=0` until R2-B Collector is ready.

**Final owner-selected Core collector hostname:** `board.nvlsup.online`
(Cloudflare DNS A record is reported by the owner to point at Core; that is
not proof the API or TLS is ready). Intended on-device HTTPS endpoint:
`https://board.nvlsup.online/api/dpt/v1/telemetry`.
Keep the existing monitored SSH Edge hostname independent from the API.
DNS IP changes behind this stable hostname do not require another flash,
subject to DNS caching and TLS certificate chain continuity. Initial
provisioning of the HMAC identity, matching hostname CA and URL does
require a deliberate firmware configuration flash. Neither DNS nor Core
is modified by R2-A.

**2026-10-31 on-device partial smoke evidence:** the operator's Serial
snippet showed three valid `[dpt-smoke] WOULD_SEND_NOT_DELIVERED` JSON
records (seq 5, 4, 3) with consistent SSH `s=1,p=52,o=255`, valid
`h.c=11` (CLOCK_NOT_READY), and 3/3 SSH PASS during 15:39-15:40.
The snippet begins mid-boot and does NOT include the `q=1` BOOT sample,
so full boot lifecycle and real TLS/HMAC/ACK remain unverified. SNTP epoch
was only 63-173 seconds, `ready=NO`; investigate this prerequisite before
enabling HTTPS delivery. Do not infer UDP/123 blocking from absent time
without independent testing. Retain the distinct R2-C hardware+collector
release gate.
