# DenaProbe R1 — Core Refactor and Hardware Validation

**Source:** R1 experimental firmware (`esp32dev_ssh_feasibility`) · **Status (2026-10-30):** source hardening and 30 deterministic host cases; ESP32 regression sign-off remains pending. Code may be integrated to `master` before field acceptance by owner request; this is **not** hardware or production sign-off. Check exact-head CI for both firmware builds.

## Scope

R1 is an internal structural refactor of the **isolated ESP32 feasibility target**. No production API, DPT/1 packet encoder, VPN client, NPV login, cellular modem, SSH channel, UDPGW, TCP tunnel or filtering verdict is added.

| Module | Responsibility |
| --- | --- |
| `ProbeConfig.h` | Historic cadence, timeouts, stack and heap constants |
| `ProbeTypes.h` | Explicit SSH result, stage trace and independent UI states |
| `SshProbe.h` | libssh experiment and pinned SHA-256 verification; distinguish Wi-Fi loss during DNS |
| `HttpsProbe.h` | Wrapper for direct-hotspot Cloudflare sample |
| `DeadlineClient.h` | Close the HTTP source on response deadline or Wi-Fi loss, within its owning worker |
| `ProbeScheduler.h` | Wrap-safe 30s/180s start-to-start timer, one active worker |
| `ProbeEvents.h` | Typed SSH/HTTPS result events via fixed 2-element FreeRTOS queue |
| `ProbeState.h` | Last-measurement freshness and separate SSH/public-HTTPS interpretations |
| `StatusLed.h` | Existing status LED patterns |
| `ProbeQuality.h` | Existing rolling 12-sample statistics and serial report |
| `ProbeDiagnostics.h` | Existing tagged SSH/HTTPS and overall Serial diagnostics |
| `ssh_feasibility_main.cpp` | Only bootstrap, Wi-Fi lifecycle, worker and event orchestration |

All modules are header-only and are compiled by a **single experimental translation unit**. This preserves PlatformIO `build_src_filter` and makes default `src/main.cpp` independent. Free functions are not yet a public SDK; split into separately compiled libraries only when the build system and unit tests are ready.

## Key change: SSH result no longer waits for HTTPS

Old: `SSH → HTTPS (if scheduled) → ONE result event`.

R1: `SSH → SSH_RESULT event → HTTPS (if scheduled) → HTTPS_RESULT event`.

The probe worker remains **serial**: libssh and TLS are not concurrently active. Main loop can consume/report SSH events immediately and show SSH failure even if public HTTPS is still in progress. `workerFinished` is set only on the last event from a worker, preventing overlapping workers. The queue is bounded (2 events); producer deliberately blocks if it cannot deliver rather than silently dropping an SSH result.

## Behavior preserved

- SSH start-to-start cadence **30 s**, HTTPS schedule **180 s**.
- SSH Transport deadline **12 s**, Service acceptance deadline **8 s**.
- Same strict pinned SHA-256 server public-key verification, no trust-on-first-use.
- Same libssh observer return `SSH_PACKET_NOT_USED` and verified vs observed stage semantics.
- No SSH login, no VPN data path, no Telegram update inference.
- Same HTTP endpoint/CA/64 KiB limit/4s body slow threshold; response timeout enforcement is corrected below.
- Same 12-probe rolling statistics, 90s SSH and 360s HTTPS freshness, and LED patterns.

Intentional diagnostic differences:
- `[ssh-stage]`, `[ssh-deep] END`, `[quality-sample]`, `[quality-window]` can appear **before** `[https-quality]`, with new `[probe-event]` completed-uptime lines.
- An HTTPS cycle yields two `[probe-overall]` lines (first SSH, then new HTTPS), rather than one delayed combined line.
- SSH resource measurements are taken at SSH completion instead of after optional HTTPS; therefore old/new heap watermarks are not identical measurement instants.
- Explicit event completion uptime is used to track freshness, rather than console-processing time.
- R1 does **not** claim to detect mobile carrier, NPV data path or filtering.

## 2026-10-30 review fixes

### Bounded HTTPS response, including silence

The old sink-only 12-second check could not stop HTTPClient when the peer kept
the connection open without delivering more body bytes or a chunk header.
`DeadlineClient` now guards the **source** operations used by HTTPClient and
Stream: `connected`, `available`, `read` and `peek`. It closes its own TLS socket
and ends a pending Stream character wait when the deadline expires. A dripped
byte does not renew the absolute deadline. No other task deletes the worker or
closes its TLS objects.

- Response headers: **20 s**, including TCP/TLS setup; TCP and TLS retain their
  own **7 s** limits. Body: a separate **12 s** budget, starting after headers.
- DNS remains the pinned framework's synchronous resolver; the response budgets
  start **after** that lookup. They are not a guarantee for total probe duration.
- TLS connects to the resolved IP using the framework's public overload that
  also receives the **original hostname and CA**. SNI and certificate hostname
  verification are preserved; this avoids resolving the same name a second time.
- Timeout before headers maps to `TLS_OR_CONNECT_FAIL`; body timeout maps to
  `BODY_ERROR`. Serial adds `deadline_exceeded=1` to identify the timeout.
- Wi-Fi loss during HTTPS DNS/header/body processing maps to `WIFI_DOWN`.
- The unexpected-worker-stall cutoff remains **55 s per phase**. Consuming the
  SSH event starts the HTTPS phase budget using that event's completion time.
  Two slow but completed phases no longer accumulate into a false stall. A
  genuine stall stays latched and disables further probes until reset.

### DNS failure classification

SSH rechecks Wi-Fi after the Edge lookup (including a cached success) and after
the independent DNS control. A disconnected hotspot yields `WIFI_LOST`; no
second lookup or SSH session starts when the link is already known down. An
actual resolver failure with Wi-Fi still connected retains `DNS_FAIL`.

### Quality window: local and remote failures are separate

`[quality-window]` preserves the existing `eligible`, `network_failures`,
`wifi_lost` and `excluded` keys for compatibility, but explicitly corrects
their counting semantics:

- `eligible` includes only completed SSH-path outcomes (PASS, DNS fail,
  transport failure/timeout, or service request failure/timeout).
- `network_failures` includes only failed **eligible SSH path** samples.
  `WIFI_LOST` must never increment it or the eligible denominator.
- `wifi_lost` counts local hotspot link-loss samples, and `local_failures`
  counts those plus local allocation / SSH-option errors.
- `trust_failures` counts host-key unavailable/mismatch separately.
  `excluded` includes all local and trust failures.
- Rolling counts represent only the last 12 SSH samples. No counter is a
  carrier-filtering verdict, and no SSH-authentication or NPV path is tested.

Four extra deterministic cases verify Wi-Fi-only, mixed SSH/Wi-Fi, trust/resource
errors, and 12-sample eviction. The classification changes are serial-only;
DPT/1 wire interpretation and backend alerting remain future R2 work.

### Build and host regression coverage

The build is pinned to PlatformIO **6.2.0** in CI, platform **espressif32 8.0.0**,
Arduino framework package **4.30312.261024** (Arduino **3.3.12**) and SDK libraries
**3.3.12**. libssh retains its original pinned commit. CI runs for every PR and
for pushes to `master` / `feature/**`, with host tests preceding both builds.

```sh
python tests/run_host_tests.py
```

The 30 deterministic host cases compile the real R1 entrypoint/modules against
fake peripherals. They cover silent fixed/unknown-length bodies, stalled chunk
headers, slow-drip headers/body, successful/slow/short/oversize samples, TLS
rejection, DNS and mid-body Wi-Fi loss, host-key rejection, SSH/service timeout,
timer wrap, freshness, independent event order, no overlapping workers, next
probe after HTTPS timeout and latched genuine stalls. The HTTP adapter models
the relevant source access patterns; it does **not** validate the real TLS
stack, HTTP parser, FreeRTOS scheduling or board heap. The two firmware builds
check compatibility with the real pinned APIs; physical checks below remain
necessary. Test-only public fixtures in `tests/stubs/` never enter firmware.

DPT/1 independent HTTPS wire events, serializer, API delivery and notifications
remain later work. This R1 change does not alter their schema or implement them.

## Release checklist — automated

Build both environments and compare baseline semantics. The repository's R1 build workflow compiles both targets:

```powershell
cd D:\denaProbe\DenaProbe
git fetch
git switch master
git pull --ff-only
pio run -e esp32dev
pio run -e esp32dev_ssh_feasibility
```

No private `include/probe_private.h` is committed; local hardware configuration and verified pin remain on the operator's machine.

## Release checklist — ESP32 field test

1. Flash **experimental environment only**: `pio run -e esp32dev_ssh_feasibility -t upload`.
2. Start Monitor with durable file logging: `pio device monitor -b 115200 -f time -f log2file`.
3. Validate at least 12 consecutive SSH results; `[quality-sample] seq` increments once per **SSH** result, not HTTPS. Historical 30s start cadence should remain approximately stable.
4. On each 180s HTTPS cycle, confirm SSH `[probe-event] type=SSH_RESULT` and `[ssh-deep] END` arrive **before** HTTPS `[probe-event] type=HTTPS_RESULT` and `[https-quality]`.
5. Confirm independently new HTTPS samples: `https_new_sample=1` **only** on the HTTPS result, never on the preceding SSH result. Stale previously measured HTTPS must carry its original seq and age; never recast as new.
6. Trigger Wi-Fi loss/recovery; confirm only Wi-Fi / local status, not asserted operator filtering; catch `workerFinished` lifecycle, no overlapping probes or crash.
7. Test SSH endpoint outage, invalid host key (must fail closed), post-transport service failure and HTTPS slow/error separately. Confirm LED modes and `filtering_verdict=INCONCLUSIVE`. During DNS, switch off the hotspot and check `WIFI_DISCONNECTED`, not `DNS_FAIL`.
8. With a controlled test response, stall body/chunk delivery while TCP stays open. Expect `BODY_ERROR`, `deadline_exceeded=1`, a completed HTTPS event and another SSH cycle. Dripped headers must terminate within their response budget. If temporarily changing the HTTPS fixture endpoint, use a matching trusted CA and hostname; never disable verification. Restore the real endpoint before deployment.
9. Watch heap, largest block, watchdog, 30s cadence and long-run stability. On a genuine worker stall, further probes must be disabled; do **not** automatically delete a crypto worker. Record the tested firmware commit and synchronized Serial / NPV reference observations.

**Release gate:** code-only integration to master is permitted once automated checks pass; the field tests above remain mandatory **before declaring R1 hardware-validated or activating remote/production telemetry**. Do not confuse a successful build with operational acceptance. This refactor is not DPT/1 telemetry transport R2 or VPN data-path probing.

