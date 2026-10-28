# Phase 1B.1 — SSH feasibility firmware (experimental)

**Scope:** Build and field-test SSH transport (KEX/NEWKEYS as a combined result), SHA-256 SSH host-key pinning, and a no-credential `ssh-userauth` SERVICE_REQUEST/SERVICE_ACCEPT round-trip on the ESP32 DevKit.

This is **not** the Phase 1B finished diagnostic engine. **No passwords, usernames, SSH user authentication, VPN traffic, bot integration or production changes.**

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

**No CI, build, flash or physical hardware validation has been run by this documentation change.**
