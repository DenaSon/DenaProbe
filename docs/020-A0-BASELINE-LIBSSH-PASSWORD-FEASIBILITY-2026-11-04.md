# DenaProbe A0 — Baseline audit and libssh Username/Password feasibility
**Date:** 2026-11-04  
**Decision:** **GO for A1 source-only password-auth refactor; NO-GO for physical Deep activation until the A1/A2 gates pass.**  
**Status:** A0 source/CI audit COMPLETE; live board/SSH server preflight STILL OPEN.  
**Scope owner:** ESP32 DenaProbe, not production Core. This file records evidence only: no Firmware, bot, Collector, user account or server change.

Canonical scope: [017 — Password Deep SSH and representative NPV data path](017-DEEP-SSH-PASSWORD-DATA-PATH-FIELD-PLAN-2026-11-04.md).

## 1. Pinned evidence inventory

| Evidence | Revision / observation | Verification |
|---|---|---|
| DenaProbe `master` at A0 start | `68462f629bc4b28bfd07b4052ff8a8f5345a3423` | GitHub git ref, 2026-11-04 |
| Existing NVLBot master | `c0e9fcce85c14e9c731c8d2627bdc8486e4ba644` | Previous approved R3 rapid D0 alert release; **not changed** |
| LibSSH-ESP32 dependency | `ewpa/LibSSH-ESP32#343fce1c5d1d0e3d629807dece6ae1b68ef1d322` | Exact immutable `platformio.ini` dependency |
| Upstream port release | README names libssh **0.11.5** (stable 0.11 port), updated 2026-07-21 | [Pinned upstream README](https://github.com/ewpa/LibSSH-ESP32/blob/343fce1c5d1d0e3d629807dece6ae1b68ef1d322/README.md) |
| ESP32 framework | `espressif32@8.0.0`; Arduino package `4.30312.261024`, libs `3.3.12` | `platformio.ini` |
| Host/PlatformIO tests | 2026-11-04 PR #13: host and PlatformIO jobs SUCCESS | [CI](https://github.com/DenaSon/DenaProbe/actions/runs/41821307426) |
| Experimental Deep build | 2026-11-03 previous `master` R3 compile CI SUCCESS | [CI](https://github.com/DenaSon/DenaProbe/actions/runs/41634609984) |
| Physical existing monitor | Operator's prior DPT/2 TCP/SSH preauth, D0 warning, native Telegram delivery and recovery confirmed | Historical field conversation only; *not a Deep hardware result* |
| Actual installed firmware SHA, physical 4MiB flash and partition bytes | **UNKNOWN until board/serial inspection** | Must not substitute repository build configuration for a reading from the actual device |
| Exact on-host OpenSSH authentication and forwarding policy | **UNKNOWN until read-only Server/NPV reference inspection** | Existing source statements about Edge-as-Relay are not a live `sshd -T` result |

Historical source reports should not be construed as proof of today's running Core, Edge or physical ESP32 binary.

## 2. Build baseline (observed CI, exact numbers)

The base environment and experimental feasibility environment use **different app-partition maxima**. Compare bytes within each environment, not percentages alone.

| Build env | App used | Maximum app | Free headroom | Reported static RAM used | Result |
|---|---:|---:|---:|---:|---|
| `esp32dev` / legacy default | 954,748 B | 1,310,720 B | 355,972 B | 47,008 / 327,680 B (14.3%) | PASS, 2026-11-04 |
| `esp32dev_ssh_feasibility` / current transport monitor | 1,421,016 B | 1,966,080 B | 545,064 B | 65,796 / 327,680 B (20.1%) | PASS, 2026-11-04 |
| `esp32dev_r3_deep_compile` / existing key-auth Deep | 1,566,624 B | 1,966,080 B | **399,456 B** | 65,804 / 327,680 B (20.1%) | PASS, 2026-11-03 |

**Deep-vs-feasibility binary delta:** +145,608 B; this is the current **key-auth build**. It is NOT the future password-auth image size and NOT hardware-proven.

- Base `esp32dev` compiles `src/main.cpp` and intentionally has no Deep runtime.
- Feasibility and Deep builds compile `src/ssh_feasibility_main.cpp`; use `board_build.partitions = min_spiffs.csv`, with a CI-reported 1,966,080 B app capacity. The partition CSV is provided by the framework, not checked into this repository.
- The opt-in Deep compile uses `-DPROBE_DEEP_ENABLED=1`; no real key or password is provisioned in CI.
- Static `RAM` figure includes neither live heap fragmentation nor network/crypto/library dynamic allocations during SSH authentication/channel transfers.
- Actual ESP32 RAM/flash and partition layout must be confirmed locally before flashing.

**Risk:** A binary that passes the 1,966,080 B size limit can still crash or fail in the presence of insufficient contiguous heap during live libssh plus Wi-Fi/HTTPS/Telemetry work. Save the known-good actual firmware and local ignored private configuration before physical pilot. Experimental partition changes are not implicitly applied by docs.

## 3. Feasibility of Username/Password in EXACT pinned libssh port

Direct inspection of the pinned upstream files confirms:

- `src/libssh/libssh.h` declares `ssh_userauth_password(ssh_session, const char *username, const char *password)`.
- The pinned `src/auth.c` contains the actual `ssh_userauth_password` implementation, not only a prototype (around line 1639).
- `src/libssh/libssh.h` and `src/auth.c` also provide the keyboard-interactive family (`ssh_userauth_kbdint`, prompt read/set functions).
- `ssh_channel_open_forward` is declared and already used by our experimental `DeepSshProbe.h`.
- The current `SshProbe.h` uses `ssh_set_blocking(session, 0)`. Password auth therefore needs bounded repeated calls when `SSH_AUTH_AGAIN` is returned, with a deadline and explicit `SSH_AUTH_SUCCESS`, `DENIED`, `PARTIAL`, `ERROR` distinctions.

Pinned port references: [header](https://github.com/ewpa/LibSSH-ESP32/blob/343fce1c5d1d0e3d629807dece6ae1b68ef1d322/src/libssh/libssh.h) · [implementation](https://github.com/ewpa/LibSSH-ESP32/blob/343fce1c5d1d0e3d629807dece6ae1b68ef1d322/src/auth.c). Upstream function semantics: [libssh authentication API](https://api.libssh.org/master/group__libssh__auth.html).

**A0 conclusion:** technical *source-level feasibility* of Username/Password is established. The actual password method permitted by our SSH server and real ESP32 execution/memory behavior have **not** been tested. Do not silently broaden into keyboard-interactive without proving the target requires it; if required, support its prompt protocol safely and treat unexpected multi-factor prompts as unsupported, not auto-answer arbitrary prompts.

**Security invariant:** client password authentication never replaces **server host public-key pinning** (`PROBE_SSH_PIN_SHA256_HEX`). Host-key mismatch must abort before sending a password.

## 4. Existing code architecture and exact refactor impact

### Already present

- `src/denaprobe/SshProbe.h`: fresh DNS, independent TCP preflight, nonblocking SSH transport/KEX, independently pinned host public-key SHA256, `ssh-userauth` service request, optional Deep invocation.
- `src/denaprobe/DeepSshProbe.h`: conditional `PROBE_DEEP_ENABLED`, `deepSettingsValid()`, private-key-only auth via `ssh_pki_import_privkey_base64` + `ssh_userauth_publickey`; authenticated `ssh_channel_open_forward`, separate two fixed-body transfers, length/content checking, 20-second default dwell.
- `src/denaprobe/ProbeConfig.h`: 30,000ms base probe interval; 180,000ms independent HTTPS; worker stack setting 51,200 bytes, heap preflight threshold 110,000 bytes; experimental Deep worker max-stall bound 105,000ms.
- `src/denaprobe/TelemetryCodec.h`: DPT/2 fields `c`, `z`, `f`, `g` (opt-in), no password in wire format.
- `include/probe_private.h.example`: local-only/ignored configuration template, current private-key requirement in Deep.
- `tests/stubs/libssh/*`, `tests/run_host_tests.py`: deterministic host regression harness, currently **not proof** that password authentication works on the ESP32.

### Required source-only A1 changes, minimal

1. Add an explicit password-auth mode and local-only `PROBE_DEEP_PASSWORD`. Keep `PROBE_DEEP_USER`; validate nonempty bounded password and user, require verified host pin; remove the **private-key requirement only for this password mode**. Never put actual credentials in source/default `*.example`, tests or CI.
2. Extract `performPasswordAuth(session)` (or equivalent) with nonblocking `SSH_AUTH_AGAIN` retry, bounded timeout and error mapping. Set `SSH_OPTIONS_USER` **before connect**; the existing `deepSettingsValid()` currently tests a private key and gates username configuration, so it must be refactored together with authentication, not changed in isolation.
3. Preserve the normal non-Deep firmware and all previous DPT/2 code numbers (10 rejected, 11 timeout, 12 error, 90 local unknown). Include tests that wrong password never becomes a filtering incident.
4. Reuse the existing constrained `direct-tcpip` channel and two-transfer worker; do not add arbitrary forwarding, shell or PTY. Explicitly mark missing permitted responder as NOT_TESTED.
5. Record stage timing, actual requested/received bytes, heap/min/largest-block/stack watermark, worker elapsed and reason codes without logging credentials.
6. Keep Core, SSHD, Collector, bot and production routes untouched in A1.

## 5. Real-hardware timing and data-budget risks

- Feasibility scheduler starts SSH worker approximately every 30s **only when no worker is already active**. With Deep enabled, the worker may remain active during authentication, first 16KiB, **20s dwell**, second 16KiB and telemetry serialization. Real start-to-start cadence therefore cannot remain guaranteed at 30s.
- Existing Deep frequency defaults every **two successful transport cycles**. This is not a guarantee of fast D1/D2 notification: detection delay includes Deep sampling, dwell, completion, signed telemetry, server classifier tick and Telegram delivery.
- Current fixed-body budget: **2 × 16KiB = 32KiB per Deep run**, not counting protocol overhead or the 64KiB HTTPS control every 3min. At one run/minute continuously, this is **45MiB/day** of Deep payload alone. Pilot interval must be bounded and measured, not automatically enabled for continuous performance testing.
- Assure on physical board: no watchdog resets, heap exhaustion, failed concurrent TLS/SSH, FIFO overflow or dishonest stale state. Existing D0 rapid alert must be preserved.
- A single successful password auth still does **not** prove SSH forwarding, data-plane health or full NPV client equivalence.

## 6. Target-path audit gate (not yet accomplished)

The operator chose a real NPV-facing SSH hostname/port and one SSH identity for the pilot. Their live values are deliberately excluded here. Before requesting board firmware flash, verify **without production writes**:

- Same hostname, port and TLS/SSH-facing route as the actual NPV user from the MCI hotspot; avoid testing a bypass address that NPV never uses.
- Which host actually terminates SSH (Edge relay vs Core); account expiration/lock behavior and effective PasswordAuthentication/KbdInteractiveAuthentication in server configuration.
- Whether userauth uses password or interactive challenge; whether `direct-tcpip` channels are authorized for that test account and which destination host/port is permissible.
- Whether a deterministic responder already exists **on the terminating host**; none is currently attested. Without it, the A2 test can confirm authentication and channel-policy behavior, but may not claim valid fixed-body transfer.
- Confirm true firmware build SHA and the board's flash size/partition layout from an actual connected board before flashing; no assumption that the CI environment matches live flash.
- Compare NPV client baseline and Deep result from the **same hotspot/operator and target**, not different Edge IPs. A Core localhost responder tests authenticated forwarding but not NPV egress unless explicitly shown equivalent.

Account renewal with unchanged username/password does not inherently require flashing; credential rotation would require local reprovisioning in this intentionally no-OTA/no-Remote-Config scope.

## 7. A0 evidence checklist and handoff

| Gate | Result at A0 | Evidence needed to close |
|---|---|---|
| Exact repo / dependency pins | **PASS** | `platformio.ini`, SHA above |
| Existing known-good default and feasibility builds | **PASS (CI)** | 2026-11-04 host/PIO log |
| Existing key-auth Deep compile | **PASS (CI only)** | 2026-11-03 R3 log |
| Password libssh API present in exact pin | **PASS (source inspection)** | Pinned upstream libssh header and auth.c |
| Same-build link/runtime of NEW password auth | **NOT TESTED** | A1 new isolated password-auth build and real A2 device |
| Actual ESP32 flash/partition/binary snapshot | **PENDING** | Hardware/Serial or read-only flash information |
| Actual server auth and forwarding rights | **PENDING** | Authorized read-only SSHD configuration and user-path inspection |
| Valid host-key pin for target | **PENDING operator re-confirmation** | Independent verified fingerprint, no TOFU |
| Real Heap, largest block, stack, watchdog in Deep | **NOT TESTED** | A2 Serial over bounded repeated sessions |
| No DPT/2 or existing D0 regressions | **BASELINE CI PASS; A1 regression pending** | A1 host + cross-language contracts, A2 field |

### GO / NO-GO

**GO now:** A1 **source-only** libssh Username/Password refactor and its negative/positive tests in a separate PR, with existing non-Deep default untouched. No account/SSHD changes; no device flash or Core deployment from this A0 report.

**HOLD:** A2 physical enablement until password build and source tests pass and the owner approves the pilot after checking true board flash/partition and server-side authentication/forward policy. Do not propose a Core/Telegram rollout before A2 acceptance.

### Recommended verification when the operator is at the Windows workstation (non-destructive)

```powershell
# From the existing local DenaProbe checkout, no upload:
git rev-parse HEAD
pio run -e esp32dev
pio run -e esp32dev_ssh_feasibility
pio run -e esp32dev_r3_deep_compile

# With board connected, inspect device hardware without flashing:
pio device list
python -m esptool --chip esp32 --port COM6 flash_id
```

Command names, COM port and package installation may differ on that PC; capture output only, not credentials or copied local private headers. Record the actual running firmware version and existing known-good binary separately before A2.

**A0 audit changes:** this document only. No application code, build file, secret, host-account, production or test target is mutated.
