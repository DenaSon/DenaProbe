# DenaProbe Lite — MCI SSH access + transfer (Board Phase 1)
Date: 2026-11-04. Source candidate. NOT YET FLASHED or accepted by hardware.

## What the instrument actually measures
ESP32 on MCI in Iran → public NPV Edge DNS/TCP:2252 →
SSH handshake + pinned Ed25519 host key → existing test username/password
on the SSH terminator → one authenticated direct-tcpip SSH session →
two **separate 8KiB 0x5A TCP payloads**, 5s apart, from an explicitly
approved first-party **public TCP responder** reached from the terminator.
No complete NPV application traffic, no client SOCKS implementation, and no
guarantee that public responder performance matches all customer destinations.
Core/Edge-to-Core transit is not measured as a separate benchmark. It is part
of the authenticated inbound SSH path. No direct public 64KiB HTTPS quality
benchmark in Lite (HTTPS signed telemetry itself remains enabled).

## Important operational prerequisite
The already-proved loopback responder `127.0.0.1:18180` is NOT an acceptable
Lite witness. A stable first-party public host/port must be approved and serve
8192 bytes of `0x5A` automatically upon each new TCP connection. Configure
only LOCAL ignored `include/probe_private.h`:
  `PROBE_EDGE_HOST`: existing public SSH front door (unchanged)
  `PROBE_EDGE_PORT`: existing port 2252 (unchanged)
  `PROBE_DEEP_USER`/`PROBE_DEEP_PASSWORD`: existing disposable SSH test account
  `PROBE_SSH_PIN_SHA256_HEX`: existing verified pinned server key (unchanged)
  `PROBE_DEEP_AUTH_ONLY 0`
  `PROBE_DEEP_REMOTE_HOST`: the approved external responder (not loopback)
  `PROBE_DEEP_REMOTE_PORT`: its actual TCP port
Existing SSHD per-user `PermitOpen` or `AllowTcpForwarding` may restrict
non-loopback destinations. Do not change global SSHD or production credentials
automatically; have an operator verify and approve only this one target.
Missing/invalid public host => SSH password login is still tested,
but the transfer is explicitly NOT_TESTED (no channel opens). Unauthorized
forwarding or an absent responder => CONFIG/UNKNOWN until independently
verified. Never infer carrier filtering from these alone.

## Lite build and safety gates
Build: `esp32dev_lite_compile`.
  - Password login always follows verified SSH host-key pinning.
  - Deep auth runs once in the same SSH session as both transfer probes.
  - 8192 bytes required per sample; validate each byte == `0x5A`; fail on
    short, wrong or missing data. Bounded reads, channel and auth deadlines.
  - 5s dwell probes post-login stalling. No artificial 20s wait.
  - Wire Stage 1 **masks** all Deep data and Auth from DPT/2: old Core
    continues receiving signed DNS/TCP/preauth SSH measurements and alerts
    without new field rejection. Serial contains the true auth/data result.
  - No credential, hostname, payload dump or username logged on Serial.
  - Local Wi-Fi loss, SSH pin mismatch and rejected password are separate,
    not automatic MCI-filtering verdicts.

## Core Phase 2 — reserved, NOT safe to flash yet
Build: `esp32dev_lite_wire_compile`.
The new signed DPT/2 payload uses:
  `"j":{"u":auth_uptime,"s":auth_code,"ms":duration_ms}`
  `"ei":"192.0.2.1"` (example: actual IPv4 returned by the board's Edge DNS;
   omitted on DNS failure; only sent by the coordinated Lite wire profile)
  `"z":{"u":deep_uptime,"s":deep_code,"am":auth_ms,"sm":session_ms,"rt":2,
        "f":{"s":first_code,"r":8192,"n":received_1,"ms":elapsed_1},
        "g":{"s":second_code,"r":8192,"n":received_2,"ms":elapsed_2}}`
The old top-level `a` remains SSH SERVICE_ACCEPT duration; do not reuse.
The installed Core validator permits `rt=1` only. Core update must explicitly
allow `rt=2`, store independent Auth `j`, classify D0/SSH login and stalled
DATA separately with controlled-target-health guards, and render Rich Telegram
incidents/recovery. **Until then the Lite Stage 1 firmware must not send j/z.**
Missing DPT uploads require a device-silent/UNKNOWN signal, not an SSH verdict.

## Source acceptance checklist
- Run host tests in `tests/run_host_tests.py` for normal baseline/B1/B2/B3,
  plus Lite success, short or invalid data, second read stall, rejected auth,
  wrong pin, local loss, and backward-compatible and future signed DPT/2.
- CI compile `esp32dev_lite_compile` and `esp32dev_lite_wire_compile`,
  together with known-good default and previous controlled builds.
- DO NOT flash until Core/external first-party responder/SSH permission
  preflight is approved. Preserve previous B2 rollback firmware.
- For a future board field run: observed `AUTH_SUCCESS`; both transfer
  codes=1 and 8192/8192; 5s dwell; DPT2 HTTP200 ACK and no j/z in old Core.
  B2 Core-loopback success alone is not evidence of external transfer health.

No modifications to Core, Telegram, schema, or production SSHD in Board Phase 1.
