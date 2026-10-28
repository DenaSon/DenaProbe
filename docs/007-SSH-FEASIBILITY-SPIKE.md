# Phase 1B — SSH stage and quality capture (experimental)

**Scope:** Build and field-test SSH transport (KEX/NEWKEYS as a combined result), SHA-256 SSH host-key pinning, and a no-credential `ssh-userauth` SERVICE_REQUEST/SERVICE_ACCEPT round-trip on the ESP32 DevKit.

This is **not** the Phase 1B finished diagnostic engine. **No passwords, usernames, SSH user authentication, VPN traffic, bot integration or production changes.**

## Phase 1B.2 — SSH stage visibility (field-observed on hotspot)

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

### Hardware observations

- Phase 1B.1 was built and uploaded by the owner on the actual ESP32.
- Multiple `SERVICE_ACCEPT_PASS` results with a matching trusted Core ED25519 host key.
- Hotspot off => slow LED; reconnect => steady LED on subsequent SSH success.
- A deliberately incorrect local pin => `HOST_KEY_MISMATCH` and `service_ms=0` (no service request).
- Phase 1B.2 was subsequently built and uploaded: real ESP32 log included `KEXINIT_TX=448ms`, `KEXINIT_RX=643ms`, `NEWKEYS_RX=2045ms`, SSH transport `3282ms`, and `SERVICE_ACCEPT_PASS` with a pinned host-key match. These are successful SSH stage observations, **not evidence of download throughput**.


## Phase 1B.3 preview — SSH Quality Capture (NOT hardware validated)

**Purpose:** collect repeatable, low-cost measurements **now** during a reported slowdown without automatically declaring a VPN speed problem.

This experimental firmware uses one no-auth SSH check every **30 seconds** (rather than 60 seconds), retains a **12-result ring buffer** in RAM (about six minutes), and emits:

- `[quality-link]`: Wi-Fi hotspot UP/DOWN transitions with uptime timestamp and cumulative Wi-Fi drop events since boot, including drops that occur between scheduled SSH probes.
- `[dns-diag]` (on `DNS_FAIL` only): logs phone-hotspot-configured primary/secondary DNS and gateway IPs, then resolves an independent control name (`example.com`) **via the current system resolver**. `control_resolve=PASS` + Edge DNS fail suggests a hostname-specific resolution issue; both failed suggests a broader DNS issue. Neither is proof of filtering, full internet access or a throughput problem. Control may fail on a restricted link; all outcomes remain `cause=UNCONFIRMED`.
- `[quality-sample]`: sequence, timestamp since boot, measured hotspot **Wi-Fi RSSI** (never LTE signal), DNS, SSH transport, service-accept durations, and observed KEXINIT / NEWKEYS elapsed-time gaps. The latter are timing intervals, **not** pure crypto execution durations or packet RTTs.
- `[quality-window]`: number of eligible runs, successes, connectivity failures (Wi-Fi loss, DNS, transport or service failures), separately counted Wi-Fi losses, excluded local security/resource errors, SSH transport p50/p90, span (max-min), and DNS/service p50 calculated **only from successful runs**.
- `download_speed=UNKNOWN`, `throughput=NOT_TESTED`, `packet_loss=NOT_MEASURED`: avoids claiming any data-transfer measurement. Handshake timing cannot establish bandwidth, real VPN performance, or cellular packet loss.

Status `ssh_latency_flag`:

- `COLLECTING` before four eligible results.
- `PATH_FAILURES_OBSERVED` if at least two failures fall in the 12-result window. This is **not** an attribution to MCI filtering, Edge, WireGuard, or Core.
- `BASELINE_NOT_CALIBRATED` if there is no trusted healthy SSH latency reference; importantly, an active incident is **not** a safe time to automatically train a "healthy" baseline.
- `SLOW_HANDSHAKE_SUSPECT` only if a trusted reference and a decision threshold have **both** been configured, with at least four successful samples and the transport median exceeding that explicit threshold.
- `NO_SSH_LATENCY_ALERT` when a trusted threshold is present but has not triggered; this does **not** mean download speed is normal.

Optional private (ignored) macros are `PROBE_QUALITY_HEALTHY_TRANSPORT_MS` and `PROBE_QUALITY_ALERT_RATIO_PERCENT`. **Both default to zero: no speculative slowdown classifications.** Configure them only after measuring validated healthy and slow reference samples; do not derive from this capture alone. Neither is a network identifier or a private password, but keep private settings out of Git.

The buffer contains only volatile, aggregate metrics. It is cleared after reset and has no NVLBot integration, persistence, traffic generation, SSH login or remote configuration. The onboard LED still reflects connectivity to SSH service, not the quality flag.

**Capture procedure (PowerShell):** `git pull --ff-only`, then `pio run -e esp32dev_ssh_feasibility`, then `pio run -e esp32dev_ssh_feasibility -t upload`, then `pio device monitor -b 115200`. Run one command at a time. Keep the phone connected to the **MCI LTE hotspot**, do not switch carriers during one window, and record the contemporaneous NPV Tunnel slowdown separately. Capture at least 12 samples / approximately six minutes. Compare with a later known-good window on the same path. Do not label the device's Wi-Fi RSSI as LTE signal.

**Acceptance pending:** successful PlatformIO build and flash; no restart, watchdog or heap trend; 12-sample wrap without corruption; Wi-Fi-off recovery; and comparison against a real healthy/slow reference. Do not merge until approved.

### Field observation — 2026-10-29 incident

Four consecutive DNS failures were captured 30 seconds apart after the ESP32 hotspot Wi-Fi went UP. Target name resolution failed quickly (about 10–16 ms); SSH KEXINIT, NEWKEYS and SERVICE_ACCEPT were correctly `NOT_TESTED`. The quality window reported `PATH_FAILURES_OBSERVED` at eligible=4/pass=0, with Wi-Fi RSSI between approximately −50 and −61 dBm. This establishes **DNS-stage failure on this hotspot path**, not download speed reduction, a server outage, censorship, or a hardware defect. The follow-up DNS-control probe was added to distinguish target-specific from broader resolver failure. **Its first local build, upload and hardware validation remain pending.**

## Phase 1B.3 — Independent HTTPS 64 KiB sample (source ready, not yet built or field-tested)

This update adds a **separate, sequential** public HTTPS sample after the SSH session has closed. It does **not** create an SSH channel, authenticate, use NPV Tunnel, or claim to reproduce Telegram downloads.

- Destination: Cloudflare's published speed-test download API `https://speed.cloudflare.com/__down?bytes=65536` (one fixed external service). A successful sample is **not** evidence that Telegram, NPV or the rest of the Internet is fast. A failed sample is not necessarily MCI filtering.
- HTTPS transport uses `WiFiClientSecure` and an embedded **GTS Root R4** public CA certificate (root trust anchor SHA256 `349DFA4058C5E263123B398AE795573C4E1313C83FE68F93556CD5E8031B3C7D`). Certificate chain and hostname validation remain enabled; **no setInsecure, redirects or HTTP downgrade**. If Cloudflare rotates its issuing CA, a certificate failure may be endpoint/configuration-specific.
- TLS requires a valid clock; asynchronous SNTP starts when the device boots. If the clock is unsynchronized, result `CLOCK_NOT_READY` is `UNMEASURABLE`, **not** network failure. A resource guard avoids trying TLS without minimum free heap and contiguous block.
- Sample size capped at **65,536 bytes (64 KiB)**. HTTP body is discarded as it arrives using a bounded stream sink, including HTTP chunked responses; no payload retained. Refuse larger/mismatched bodies. Short per-connection and read timeouts, and a 12-second body-duration cap. Hostname is resolved anew; no request credentials, user data or Core IP used.
- Scheduled at most every **180 seconds** while Wi-Fi and SSH monitoring continue every **30 seconds**; asynchronous NTP failures can be checked again next cycle. Continuous usage is approximately **30 MiB/day** from payload alone, plus TCP/TLS overhead, so this experiment must be disabled after capture if mobile data is limited (`PROBE_HTTPS_QUALITY_ENABLED=0` in ignored private config). Do not run unattended as a production speed test.
- Serial output: `[https-quality]` reports `result`, `bytes`, DNS time, HTTP header-completion time including TLS and response, first-body time, body-transfer duration and **approximate** KiB/s for the 64 KiB sample. The latter is **not a full-bandwidth benchmark**, RTT, packet loss, or VPN speed. A short sample with a slow transfer may emit `SLOW_64K_SAMPLE_SUSPECT`; `PASS` means the exact bytes were received under the configured time threshold, not that Telegram downloads succeed.
- `[probe-overall]` reports independent SSH and HTTPS states. For successful SSH but failed HTTPS, label `SSH_PASS_PUBLIC_HTTPS_FAILED_OR_INCOMPLETE`. If the full 64 KiB response arrives but body transfer takes **at least 4,000 ms**, label `SSH_PASS_PUBLIC_HTTPS_SLOW_SUSPECT` (conservative sample-level heuristic, not measured ISP throttling or established bandwidth SLA). If the sample was not verified, label `SSH_PASS_HTTPS_NOT_MEASURED` or `SSH_PASS_HTTPS_UNMEASURABLE`. If both tests pass promptly: `SSH_AND_PUBLIC_HTTPS_PASS_VPN_UNKNOWN`. Set the optional private macro `PROBE_HTTPS_SLOW_BODY_MS` to adjust the heuristic, or to `0` to disable it.
- Onboard LED now means **both SSH and recent public HTTPS passed** when solid. SSH failure / HTTP failure => warning pattern; SSH success with unmeasured HTTPS => partial pattern. This is only an experimental indication for the tested paths, not an NPV or Telegram health signal. Wi-Fi disconnected => slow blink.
- Security and reliability caveat: NTP may be blocked even if HTTPS works in other clients; this yields `CLOCK_NOT_READY`. Public Cloudflare speedtest routing may differ from Telegram or SSH relay. The fixed CA root may need maintenance. Only local physical testing can confirm TLS RAM budget on this ESP32.

### Hardware acceptance test (not yet executed)

1. `git pull --ff-only`; `pio run -e esp32dev_ssh_feasibility`; only after a successful build: `pio run -e esp32dev_ssh_feasibility -t upload`; `pio device monitor -b 115200 --filter time`.
2. Observe `[https-quality]` and `[probe-overall]` during the incident. `PASS` requires an actual verified 65,536-byte HTTPS response. If `CLOCK_NOT_READY`, `LOW_MEMORY`, or TLS errors occur, do **not** conclude filtering.
3. Compare with an independent browser/NPV Telegram download on the same MCI LTE connection at the same time. A direct HTTPS sample does not test the VPN tunnel or reproduce Telegram's endpoints.
4. Check watchdog, heap, stable SSH callback results and LED. Physical USB/PlatformIO build & test are outstanding; no merge is authorized.

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

- `[ssh-deep] TRANSPORT_PASS`: libssh `ssh_connect` completed KEX and NEWKEYS **combined**. 1B.2 also separately reports KEXINIT/NEWKEYS observations (not per-crypto-stage duration).
- `[ssh-deep] HOST_KEY_PASS`: received server public key matches locally trusted SHA-256 pin.
- `[ssh-deep] END | result=SERVICE_ACCEPT_PASS`: server accepted SSH userauth service request. **No user login attempted**.
- `SERVICE_ACCEPT_TIMEOUT`: request awaited but no response before deadline; does not prove filtering.
- `SSH_TRANSPORT_ERROR`: libssh failed before successful transport. It may be TCP, algorithm, key-exchange or protocol related; finer attribution is **not yet proven**.
- `HOST_KEY_MISMATCH`: abort before service request (fail closed).
- `WORKER_STALLED`: diagnostic worker did not complete within 30 seconds; further probes disabled until reboot, without unsafe task deletion.

Only `SERVICE_ACCEPT_PASS` illuminates the LED steadily (SSH_READY). An incomplete or unconfigured run never claims NPV health. Wi-Fi wait blinks slowly, in-progress/untested is 1.5s ON/0.5s OFF, failed probe is a double pulse.

The FreeRTOS worker uses a dedicated 51,200-byte stack, nonblocking SSH API, a 12-second transport deadline, 8-second service deadline and bounded frequency (30 seconds only in incident-capture variant). Free heap, minimum heap, largest 8-bit block and stack watermark are reported.

## Validation gates

1. **Build:** dependency resolves, framework compiles, flash and RAM map fit.
2. **Hardware:** no boot loop, stack overflow, watchdog or growing memory consumption over multiple cycles.
3. **Security:** wrong pin fails closed; no SSH user authentication or private values in serial output.
4. **Protocol:** service accepted on known-good path; controlled timeout can be distinguished from KEX/transport failure.
5. **Next phase:** field-validate independent HTTPS quality checks during a reported incident; VPN data-path testing remains separate and requires a new, explicitly approved design.

**1B.2 and the SSH quality-capture variant have been built and field-tested by the owner. The additional HTTPS sampling feature has NOT been built, uploaded or field-validated yet.**
