# Phase 1B.1 — SSH feasibility firmware (experimental)

**Scope:** Build and field-test SSH transport (KEX/NEWKEYS as a combined result), SHA-256 SSH host-key pinning, and a no-credential `ssh-userauth` SERVICE_REQUEST/SERVICE_ACCEPT round-trip on the ESP32 DevKit.

This is **not** the Phase 1B finished diagnostic engine. **No passwords, usernames, SSH user authentication, VPN traffic, bot integration or production changes.**

## Phase 1B.2 — SSH stage visibility (source ready; local build pending)

With the same pinned libssh Port, observe per-session connection progress and **incoming** SSH_MSG_NEWKEYS using a non-consuming packet callback. The custom observer returns `SSH_PACKET_NOT_USED` so the official libssh handler continues to validate and process the message. No SSH packets or crypto primitives are modified. This packet hook uses a **private libssh API**, so the Git commit stays pinned; compatibility is not guaranteed for future library upgrades.

Expected structured Serial events (`elapsed_ms` relative to the start of `ssh_connect()`):

- `BANNER_RX`: identification parsed by libssh (progress 0.4).
- `KEXINIT_TX` and `KEXINIT_RX`: local send and peer reception progress events (0.5/0.6).
- `KEXINIT | outcome=PASS` and `KEX_ALGORITHMS`: negotiation progressed (0.8).
- `NEWKEYS_RX | state=OBSERVED_UNVALIDATED`: incoming message reached the callback, **not** proof of successful processing.
- `KEX | outcome=PASS` and `NEWKEYS | outcome=PASS`: only if `ssh_connect() == SSH_OK` completes. Individual crypto and NEWKEYS processing durations are `NOT_MEASURED`.
- `stop_stage=...`: conservative classification; `KEX_OR_NEWKEYS_UNKNOWN` remains ambiguous when the library cannot isolate exactly where it stalled.
- `SERVICE_ACCEPT | outcome=...`: this stage is executed only after the separately validated host-key pin; it is `NOT_TESTED` on earlier failures.

The stage observer is an **instrumentation experiment**, not an independent validated filtering signature. A timeout after NEWKEYS may still be caused by Wi-Fi, Edge, WireGuard, Core, or transient loss. The `NEWKEYS_RX` observation is intentionally not a `PASS` without successful transport completion.

### Previously observed hardware results (before 1B.2 changes)

- Phase 1B.1 was built and uploaded by the owner on the actual ESP32.
- Multiple `SERVICE_ACCEPT_PASS` results with a matching trusted Core ED25519 host key.
- Hotspot off => slow LED; reconnect => steady LED on subsequent SSH success.
- A deliberately incorrect local pin => `HOST_KEY_MISMATCH` and `service_ms=0` (no service request).
- These observations do **not** validate 1B.2: its first PlatformIO build, upload, and Serial output are pending.


## Isolation

- Default `pio run` builds unchanged v0.0.4 from `src/main.cpp`.
- Feasibility build is `esp32dev_ssh_feasibility` and uses only `src/ssh_feasibility_main.cpp`.
- libssh ESP32 Port is Git-pinned at `343fce1c5d1d0e3d629807dece6ae1b68ef1d322` for reproducibility. Its security and resource suitability are **not yet field-approved**.
- SSH connects to the IPv4 address freshly resolved from the **locally configured Edge hostname**. No Core address is stored.
- SSH feasibility uses its own TCP connection, separate from the v0.0.4 banner test. Do not conflate their outcomes.
- Only the onboard GPIO2 active-HIGH blue LED is used.

## Required local private settings

Edit your EXISTING ignored `include/probe_private.h` without overwriting the file:

```cpp
#define PROBE_EDGE_HOST "YOUR_EXISTING_EDGE_HOSTNAME"
#define PROBE_EDGE_PORT 2252
#define PROBE_SSH_PIN_SHA256_HEX "64_HEX_DIGITS_OF_TRUSTED_SERVER_SSH_PUBLIC_KEY_SHA256"
```

The pin value must be **exactly 64 hexadecimal characters** (binary SHA-256 encoded as hex), derived from the **SSH host public key** verified out of band (for example, your independently trusted known-hosts key). Do not paste a password, private key, IP, customer detail or unverified `ssh-keyscan` output into it. **No trust-on-first-use:** missing/invalid pin => `NOT_TESTED`, without opening an SSH connection. The private header is gitignored; confirm with `git status` before publishing any files.

## Commands — Windows PowerShell (in the repository)

```powershell
git fetch origin
git switch --track origin/feature/1b-ssh-feasibility-20261029
pio run -e esp32dev_ssh_feasibility
pio run -e esp32dev_ssh_feasibility -t upload
pio device monitor -b 115200
```

Run each command separately. Keep v0.0.4 backed up. Never upload firmware before a successful Build and private pin review.

## Expected serial labels

- `[ssh-deep] TRANSPORT_PASS`: libssh `ssh_connect` completed KEX and NEWKEYS **combined**. Separate KEXINIT/NEWKEYS timestamps **not supported yet**.
- `[ssh-deep] HOST_KEY_PASS`: received server public key matches locally trusted SHA-256 pin.
- `[ssh-deep] END | result=SERVICE_ACCEPT_PASS`: server accepted SSH userauth service request. **No user login attempted**.
- `SERVICE_ACCEPT_TIMEOUT`: request awaited but no response before deadline; does not prove filtering.
- `SSH_TRANSPORT_ERROR`: libssh failed before successful transport. It may be TCP, algorithm, key-exchange or protocol related; finer attribution is **not yet proven**.
- `HOST_KEY_MISMATCH`: abort before service request (fail closed).
- `WORKER_STALLED`: diagnostic worker did not complete within 30 seconds; further probes disabled until reboot, without unsafe task deletion.

Only `SERVICE_ACCEPT_PASS` illuminates the LED steadily (SSH_READY). An incomplete or unconfigured run never claims NPV health. Wi-Fi wait blinks slowly, in-progress/untested is 1.5s ON/0.5s OFF, failed probe is a double pulse.

The FreeRTOS worker uses a dedicated 51,200-byte stack, nonblocking SSH API, a 12-second transport deadline, 8-second service deadline and bounded frequency (60 seconds). Free heap, minimum heap, largest 8-bit block and stack watermark are reported.

## Validation gates

1. **Build:** dependency resolves, framework compiles, flash and RAM map fit.
2. **Hardware:** no boot loop, stack overflow, watchdog or growing memory consumption over multiple cycles.
3. **Security:** wrong pin fails closed; no SSH user authentication or private values in serial output.
4. **Protocol:** service accepted on known-good path; controlled timeout can be distinguished from KEX/transport failure.
5. **Next phase:** instrument KEXINIT vs NEWKEYS separately and integrate into the original DNS/TCP/banner result model **only after explicit approval**.

**1B.2 has not yet been built, flashed or hardware validated. Prior 1B.1 hardware results must not be relabeled as 1B.2 validation.**
