# DenaProbe — Password SSH and representative NPV data-path probes
**Date:** 2026-11-04  
**Status:** APPROVED SCOPE / IMPLEMENTATION NOT STARTED  
**Primary repo:** `DenaSon/DenaProbe` (ESP32). **Companion:** `DenaSon/nvl-bot` (Core / Telegram).
**Decision:** Board-first engineering and real serial validation; Core/Telegram changes only after explicit hardware acceptance.

## 0. Problem and desired outcome

Production DenaProbe has passed an actual controlled test for D0 (TCP failure), rapid native Telegram alert (~30s observed), and recovery notification. A later real-world Edge-IP disruption was **not detected**: independent TCP and SSH pre-auth remained green and no alert was sent. Prior MCI audits show precisely this blind spot: SSH TCP/KEX/service request may work while authenticated SSH session, forwarding channel, or subsequent transfer stalls/resets. That observation is not, by itself, proof of a filtering cause.

**Goal:** reproduce as much of the *actual NPV user's SSH-forwarded data path* as the ESP32 can reliably observe. Add username/password authentication; prove actual SSH forwarding and two bounded data transfers from one authenticated session; report stage-specific evidence. Preserve the existing D0 monitor and its operational alerts.

**Not a claim:** success of SSH transport, an authenticated session, or a Core-local responder does **not** establish the health of every NPV client behavior, proxy/payload wrapper, public internet egress, or VPN application. The measured path must be explicitly labeled in telemetry/dashboard.

## 1. Fixed scope and no-go boundaries

**In scope**
- Existing ESP32 DEVKITV1, 4 MiB class assumed only after board verification, Wi-Fi to operator mobile hotspot (MCI and RighTel comparison); no cellular modem.
- Existing experimental libssh-based `src/denaprobe/SshProbe.h` and `DeepSshProbe.h`, DPT/2 signed data fields `c`, `z`, `f`, `g`.
- One operator-provisioned test SSH identity: username + password, via the **same hostname/port and front-door path as a normal NPV user**; target/port are local configuration, not hard-coded into public source.
- Pin and verify server SSH host public key **before** authentication; authenticated `direct-tcpip` channel(s); two bounded, measurable, integrity-checked transfer samples separated by dwell; serial monitor diagnostics and eventual Core telemetry.
- Explicit compile-time config under ignored local `include/probe_private.h`. A single deliberate serial flash for the pilot, not regular flashing between test runs.
- Isolated Core responder and server classifier/Rich UI changes **only after** board acceptance.

**Out of scope**
- OTA, remote configuration or password management API; separate device UI; dynamic fleet provisioning; SIM800L; automatic traffic switching; changing production NPV/GOST/DNS/Edge routes or customer accounts.
- Rotating/restoring user credentials as a side effect of probes; enabling arbitrary outbound SSH forwarding; exposing a public test responder; weakening existing SSH host-key verification.
- Logging SSH password, SSH packets, private keys, user data, or test response bodies; declaring who performed filtering.
- Modifying the Core Collector, bot, SQLite schema or production SSH configuration during **Board Phase A**.

**Secrets policy:** No live username/password, test identity, secret, personal hostname, HMAC credential or SSH private key is committed, copied into PR descriptions, test snapshots or logged to Serial/Telemetry. The supplied operational credential is only an out-of-band local pilot input. Local `probe_private.h` is gitignored and must remain so. Be explicit that a static password inside ESP32 flash can be extracted by someone who obtains physical access; use a restricted, replaceable test account, not a valuable customer identity. Rotate short/shared pilot credentials before long-term unattended use. Host-key pin is **not** a client SSH login key and remains mandatory.

## 2. Verified existing source vs. pending hardware proof

| Area | Existing source | What is not verified |
|---|---|---|
| SSH pre-auth | `SshProbe.h` implements TCP preflight, SSH transport/KEX/service request and pinned host-key SHA256. | Does not prove authenticated forwarding or NPV payloads. |
| Deep skeleton | `DeepSshProbe.h` implements **public-key-only** auth and `ssh_channel_open_forward`; two 16 KiB samples with 20 s dwell; bounded reads and error codes. | Password auth, real-board reliability, RAM budget, authenticated transfer acceptance. |
| Build | `esp32dev_r3_deep_compile` opts into Deep with `LibSSH-ESP32`; `esp32dev` retains known-good baseline. | Code-size against actual partition table and full hardware success. |
| Scheduler | Nominal SSH preauth 30 s; HTTPS 180 s; worker guard and heap/stack metrics already exist. | Deep calls are long and serialized; do not promise unchanged 30 s cadence or 90 s D1/D2 notification. |
| DPT/2 | Nested `z` + `f`/`g` fields and collector validation already exist, versioned and signed. | End-to-end real authenticated Deep observations. |
| Server witness | `nvl-bot/ops/denaprobe_static_responder.py` sends known 0x5A bytes on `127.0.0.1:18180`. | Not deployed/approved; no real forwarding acceptance yet. |

**Topology check:** The existing NVLBot source describes Edge-as-Relay with SSH user accounts on Core. Verify actual user connection termination and forwarding policy before calling a test “representative.” Connecting through Edge to a responder bound to Core loopback exercises a real inbound SSH session and forward channel, but **not necessarily the user's internet egress**. Phase B must distinguish controlled responder (deterministic D1/D2) from a separately approved forwarding-to-destination path (NPV equivalence).

## 3. Ordered development, test and acceptance phases

### A0 — Frozen baseline and feasibility preflight (no flash, no production edits)

1. Record the exact clean `DenaProbe` and `nvl-bot` Git SHAs, current board firmware build and serial baseline, backup of known-good firmware/binary, existing effective SSH host-key pin (verified independently; never accept TOFU), DPT wire and current Collector R3 status.
2. Confirm true flash capacity, current partition table, available app slot size; compare deep binary size. Existing experimental `min_spiffs.csv` is **not** proof that every device has a matching flash layout.
3. Inspect available libssh `ssh_userauth_password` support and, only if necessary, Keyboard-Interactive support on the exact pinned LibSSH-ESP32 revision. No unsupported auth fallback.
4. Determine how real NPV clients use the SSH target: endpoint, password/keyboard-interactive method, forwarding policy, actual remote channel destination, GOST/Edge hops. Validate with a controlled reference client first; do not alter SSHD yet.
5. Prepare acceptance fixtures for D0, AUTH_REJECTED/TIMEOUT, HOST_KEY_MISMATCH, channel failure, first-success-second-failure, slow/incomplete transfer, Wi-Fi loss, unsigned/stale evidence and full recovery.

**Gate A0:** baseline saved, target/termination assumptions documented, no secrets committed, `esp32dev` baseline remains buildable. If libssh password auth cannot run with allocated resources, pause and report rather than silently changing to a server key workflow.

### A1 — Firmware refactor: authenticated SSH via username/password (source-only)

**Minimal changes** around existing `DeepSshProbe.h`, `SshProbe.h`, private config template, test stubs and build/test scripts:
- Extract a small, explicit auth operation returning `AUTH_SUCCESS`, `AUTH_REJECTED`, `AUTH_TIMEOUT`, `AUTH_ERROR`, `LOCAL_UNMEASURABLE`; existing DPT/2 numeric mapping remains stable.
- Add `PROBE_DEEP_USER` and `PROBE_DEEP_PASSWORD` to local ignored configuration; remove the private-key requirement **from the password build only**, without disabling host-key pin verification.
- Use libssh password auth (possibly keyboard-interactive if the **actual server** requires it) with hard wall-clock timeouts, no retry loops on rejected credentials, no logging of secrets. Keep Deep opt-in default off, and keep the non-Deep default build unchanged.
- Preserve SSH transport preauth timings, independent TCP, direct HTTPS, FIFO signed uploads, Wi-Fi-loss guard, 1KiB DPT/2 body maximum, host-key-mismatch => UNKNOWN/security.
- Include precise serial stage names and durations: `DNS`, `TCP`, `KEX`, `HOST_KEY`, `SERVICE_ACCEPT`, `AUTH`, `CHANNEL`, `TRANSFER_1`, `DWELL`, `TRANSFER_2`, `SUMMARY`, heap/stack and queue ACK. No user/secret in outputs.

**Tests:** clean compiler builds (`esp32dev`, feasibility, password deep), cross-language DPT/2 fixtures, valid/invalid auth stubs, forced Wi-Fi drop, hostile/invalid server host key, worker timeout, heap/stack guard and queue continuity.

**Gate A1:** CI/build PASS, normal firmware behavior unchanged when Deep is OFF, bounded code/heap usage, and no secret in source/logs. No Core deployment.

### A2 — Physical ESP32 pilot: real SSH/password and Serial (still no Core/Telegram changes)

**Pilot setup:** one operator-provided test identity; same domain/port/path as NPV user; no production SSHD modifications. Flash the experimental password-enabled firmware **once** with rollback image retained. Prefer temporary test account, never an account currently serving customers. Test on MCI and RighTel with the same remote target and unmodified settings.

**Ordered test sequence**
1. **T01 baseline:** existing TCP, service accept, HTTPS, signed telemetry and serial remain sane before Deep.
2. **T02 password authentication:** verify host key independently, authenticate correctly, capture `AUTH_SUCCESS` and duration; wrong password -> `AUTH_REJECTED` (not “filtering”), account disabled/expired -> auth/configuration issue (never D1 filtering claim).
3. **T03 forwarding capability:** open a `direct-tcpip` channel to a **pre-existing, explicitly authorized destination**. A successful auth with rejected forwarding is `CHANNEL_OPEN_FAILED`, not a password failure. If no authorized responder exists, mark **DATA_TRANSFER_NOT_TESTED**; do not pretend end-to-end success.
4. **T04 two-transfer/hold feasibility:** if a permitted known-body service is already available, record bytes, checks, per-sample durations and a deliberate dwell in one authenticated session. Otherwise defer deterministic T04 to Phase B after responder provision.
5. **T05 failure isolation:** loss of hotspot => LOCAL/UNKNOWN; host-key mismatch => SECURITY/UNKNOWN; malformed or expired account => AUTH/CONFIG; TCP timeout => D0; no unauthorized forwarding attempts.
6. **T06 sustained hardware:** at least 30 bounded Deep cycles (pilot target; adjust only based on documented heap/watchdog/airtime limits), no reset/hang, unbounded heap erosion or queue regressions. Record free/min/largest block, stack watermark, worker elapsed and watchdog result. Confirm normal TCP/HTTPS continues with honest “stale” indication when Deep occupies the worker.
7. **T07 reference comparison:** Windows/NPV connection on the *same mobile operator and same target*, synchronized observation window, compare whether failed NPV connections are visible at the SSH/forwarding layer. Do not ascribe causal carrier filtering.

**Gate A2 / mandatory owner sign-off:** auth and host-key pass on real hardware; unsupported cases reported honestly; no serial secrets; stable worker and telemetry; an accurate record of **what was actually transferred**; known-good rollback validated. **Do not start Phase B or alter Core/Telegram until this gate is explicitly accepted.**

### B0 — Server/relay path design and permission review (read-only until approved)

1. Inspect actual Core SSHD account ownership, password vs keyboard-interactive policy and `direct-tcpip` permissions for the test account; differentiate host-side account expiration from network failure.
2. Identify correct deterministic responder location **after actual SSH termination**; define SSHD `PermitOpen` restricted to the exact allowed host/port, no arbitrary internet egress, no shell/PTY, no administrative/root privileges; preserve all customer accounts. SSHD changes require a separately reviewed change and `sshd -t` plus rollback.
3. Define separate labeled egress-like test destination if the actual NPV data path must be measured beyond Core loopback. Only a whitelisted, controlled endpoint, with explicit byte/rate budget and permission.
4. Establish MCI and RighTel same-target baseline and 16 KiB / 64 KiB plus dwell pilot matrix, measure actual data use. At 2×16KiB per minute, payload alone is ~45MiB/day; adjust cadence and only run deeper tests as often as resource/alert targets allow.

**Gate B0:** topology/permissions and test endpoint approved, no listener exposed on public IP, measurable equivalence limitations recorded.

### B1 — Deterministic transfer witness + DPT/2 integration (Core after A2)

- Deploy the reviewed loopback responder *only* on the SSH termination host and only on localhost; verify exact static body (0x5A), length, EOF and concurrency limits. Restrict forwarding to this endpoint. Never expose 18180 publicly.
- Exercise one authenticated SSH session / two independently opened channels, first sample success then dwell/second sample, including controlled reset, timeout, partial body and complete-but-slow conditions.
- Preserve DPT/1 and production DPT/2 ingestion; use existing `z`, `f`, `g` code registry, sender ages, target revision and signed freshness. **No DB migration by default**; propose a migration only with evidenced schema gap and separate backup/test plan.
- Check new R3 Deep events do not silently change D0 semantics; no old historical sample can trigger a fresh incident.

**Gate B1:** signed complete/partial Deep receipts, code/size/timing validation, local-only responder, clean old Collector and telemetry, real board sample accepted.

### B2 — Core classifier and native Telegram Rich alerts

- Separate observable classes: D0 TCP failure; D1 authenticated SSH session reset / channel-open failure after reliable preauth; D2 incomplete/timeout/severely slow **forwarded transfer**, backed by size-specific healthy baseline; AUTH_REJECTED, host-key and local-resource failures => CONFIG/SECURITY/UNKNOWN, **not filtering**.
- Display distinct statuses `SSH preauth`, `SSH authenticated`, `forward channel`, `transfer #1/#2`, sample age, data-path route label, measured bytes/times and last valid baseline. **Green initial SSH must not be confused with full transfer PASS**.
- Admin-only native Telegram Rich incident + recovery, deduped; avoid spamming on each sample. Keep existing fast D0 path untouched. D1/D2 sensitivity calibrated in pilot and never advertised at 30 seconds if Deep cadence/dwell prevents it.
- Track measured-completed, ingested, classified and delivered times for an actual latency distribution, not just tick interval.

**Gate B2:** fixture and integration tests for healthy, D0, D1, D2, wrong password, wrong host key, Wi-Fi loss, stale/ordered events, duplicate delivery, recovery and legacy dashboards. Only enable notifications after reviewed real evidence.

### B3 — Controlled real-world field acceptance and closeout

- Run MCI vs RighTel on same target and nearby time windows, retain baseline and deep serial (with no secrets), SQLite evidence IDs, dashboard screenshots and message delivery record.
- Reproduce “preauth green but data stalls” in a **controlled, authorized test** (not through customer traffic manipulation), including first sample good then subsequent timeout/reset. Compare with a real NPV reference client on same operator.
- Verify alert, incident lifecycle, deduplication and recovery without claiming causal DPI. Include negative cases (wrong password, account expiry, Wi-Fi down and missing telemetry).
- Record memory/data-budget impact, operational configuration, rollback and whether the sampled path truly matches NPV egress.

**Gate B3:** explicit final sign-off with known gaps; separate rollout status `SOURCE_MERGED`, `HARDWARE_ACCEPTED`, `CORE_DEPLOYED`, `FIELD_ACCEPTED`. No automatic production rollout.

## 4. Pass/fail matrix (minimum)

| ID | Condition | Board Serial | Core classification / alert |
|---|---|---|---|
| F01 | TCP reachable, SSH host-key pinned, password accepted | AUTH_PASS | No incident on auth alone |
| F02 | Wrong password or account expired | AUTH_REJECTED / CONFIG | No filtering alarm |
| F03 | Unknown or mismatched host key | SECURITY_UNKNOWN | No login; no filtering alarm |
| F04 | TCP failed, Wi-Fi up, fresh data | TCP_FAIL | Existing rapid D0; recover separately |
| F05 | TCP+preauth pass, server resets authenticated session | SESSION_RESET | D1 after corroborated Deep evidence |
| F06 | Auth pass, restricted forwarding disallowed | CHANNEL_OPEN_FAILED | Report permission/config ambiguity, not automatically filtering |
| F07 | First 16KiB complete, second times out | FIRST_PASS_SECOND_TIMEOUT | D1/D2 by specific session vs data-phase evidence, not inferred from client-side SOCKS listener |
| F08 | Both full but slow compared to valid baseline | TWO_COMPLETE_SLOW | D2 only after calibrated evidence |
| F09 | Hotspot disconnects or heap below guard | LOCAL_UNMEASURABLE | UNKNOWN; no false recovery |
| F10 | Old/stale/out-of-order queue event | HISTORY_ONLY | No new/closed incident |
| F11 | Two current, verified successful recovery samples | RECOVERED_EVIDENCE | One scoped recovery notification |
| F12 | Repeated identical bad samples in same episode | DEDUP | No alert flood |

## 5. Instrumentation, risks, and rollback

**Serial (sample format; NOT measured results):**
```text
[deep] transport=PASS host_key=PASS auth=PASSWORD_PASS auth_ms=<ms>
[deep] channel_1=OPEN first_bytes=16384 first_ms=<ms> first_code=COMPLETE
[deep] dwell_ms=20000 channel_2=OPEN second_bytes=16384 second_ms=<ms>
[deep] result=<PASS|SESSION_RESET|CHANNEL_FAILURE|DATA_TIMEOUT|DATA_SLOW>
[device] free_heap=<bytes> min_heap=<bytes> largest_block=<bytes> stack_watermark=<words>
[telemetry] wire=DPT2 queued=<n> ack=<accepted|history|retry>
```

**Risks:** ESP32 free heap/fragmentation and libssh stack needs real evidence; long Deep session competes with serialized probe/HTTPS/telemetry and may delay fast D0; shared/short password is a security liability; a Core-loopback responder cannot prove user internet egress; account expiration, password changes or forwarding policy changes are operational faults; Deep may be unavailable on a given partition. Include stop conditions for memory, watchdog resets, malformed telemetry, unapproved forwarding and credential leakage.

**Rollback:** Keep the last known-good ESP32 image; opt-in Deep OFF as default; one physical serial reflash to revert if hardware pilot fails. No Core changes in A0–A2. In B phases, restore isolated responder/SSH permit rules if they were approved and changed, and roll back only new Core modules separately without deleting DPT/2 database history. Never auto-alter live NPV routes, customer credentials or SSH service.

## 6. Required artifacts before phase advancement

- `A0_BASELINE.md`: SHAs, firmware/partition sizes, reference NPV pathway, evidence inventories.
- `A1_PASSWORD_AUTH_REVIEW.md`: code diff, build/CI results, auth mode/host-key policy, secret scan.
- `A2_BOARD_ACCEPTANCE.md`: redacted serial, at least 30 pilot cycles, memory/reboots, MCI/RighTel and T01–T07; owner sign-off.
- `B0_PATH_AND_PERMISSIONS.md`: reviewed sshd effective permissions, responder mapping, egress-equivalence boundary.
- `B1_DPT2_DEEP_E2E.md`: verified signed sample IDs, DB checks, control faults and no schema regression.
- `B2_ALERT_ACCEPTANCE.md` and `B3_FIELD_CLOSEOUT.md`: class D0/D1/D2 vs UNKNOWN, notification/recovery evidence, matched-operator baseline, rollback, unresolved limitations.

## 7. Decision record / explicit implementation gate

**Now:** document-only scope approval. Begin A0 then A1 only after a separate “start implementation” request. A2 requires manual ESP32 serial flash and real-board operator validation. Do not make Core/Telegram changes before owner accepts the A2 report. Password is for the SSH client identity, not the SSH host-key pin or DPT/2 HMAC device credential. Full NPV fidelity remains a measured, bounded objective rather than a binary claim.
