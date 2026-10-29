# DenaProbe R1 — Core Refactor and Hardware Validation

**Branch:** `feature/r1-core-refactor-20261029` · **Status:** implementation pending automated build and on-device regression sign-off · **No master merge.**

## Scope

R1 is an internal structural refactor of the **isolated ESP32 feasibility target**. No production API, DPT/1 packet encoder, VPN client, NPV login, cellular modem, SSH channel, UDPGW, TCP tunnel or filtering verdict is added.

| Module | Responsibility |
| --- | --- |
| `ProbeConfig.h` | Historic cadence, timeouts, stack and heap constants |
| `ProbeTypes.h` | Explicit SSH result, stage trace and independent UI states |
| `SshProbe.h` | Unmodified libssh protocol experiment, callbacks and pinned SHA-256 verification |
| `HttpsProbe.h` | Stable wrapper for existing verified, direct-hotspot Cloudflare sample |
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
- SSH Transport deadline **12 s**, Service acceptance deadline **8 s**, worker stall cutoff **55 s**.
- Same strict pinned SHA-256 server public-key verification, no trust-on-first-use.
- Same libssh observer return `SSH_PACKET_NOT_USED` and verified vs observed stage semantics.
- No SSH login, no VPN data path, no Telegram update inference.
- Same HTTP endpoint/CA/64 KiB limit/4s body slow threshold.
- Same 12-probe rolling statistics, 90s SSH and 360s HTTPS freshness, and LED patterns.

Intentional diagnostic differences:
- `[ssh-stage]`, `[ssh-deep] END`, `[quality-sample]`, `[quality-window]` can appear **before** `[https-quality]`, with new `[probe-event]` completed-uptime lines.
- An HTTPS cycle yields two `[probe-overall]` lines (first SSH, then new HTTPS), rather than one delayed combined line.
- SSH resource measurements are taken at SSH completion instead of after optional HTTPS; therefore old/new heap watermarks are not identical measurement instants.
- Explicit event completion uptime is used to track freshness, rather than console-processing time.
- R1 does **not** claim to detect mobile carrier, NPV data path or filtering.

## Release checklist — automated

Build both environments and compare baseline semantics. The repository's R1 build workflow compiles both targets:

```powershell
cd D:\denaProbe\DenaProbe
git fetch
git switch feature/r1-core-refactor-20261029
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
7. Test SSH endpoint outage, invalid host key (must fail closed), post-transport service failure and HTTPS slow/error separately. Confirm LED modes and `filtering_verdict=INCONCLUSIVE`.
8. Watch heap, largest block, watchdog, 30s cadence and long-run Stability. On Worker stall, further probes must be disabled; do **not** automatically delete a crypto worker.

**Do not merge** before successful compile and the above field tests. This refactor is not DPT/1 telemetry transport R2 or VPN data-path probing.
