# DenaProbe R3 — lightweight monitoring-only firmware closeout (2026-11-03)

## Decision and boundaries

For the current physical pilot, **Deep SSH is deferred**. ESP32 is a small passive
observer, not an NPV client, SSH account consumer, or autonomous filtering oracle.
The transport target remains `PROBE_EDGE_HOST` (currently the operator's
`n1.nvlsup.com:2252`), which resolves through the selected Edge to the Core
SSH service. Do **not** hardcode a changing Edge IP or modify Core SSH, customers,
Edge, GOST, DNS, or relay routing to run this pilot.

## What the normal `esp32dev_ssh_feasibility` build does

- Joins the configured 2.4 GHz phone hotspot; reconnects after a link failure.
- Every 30 seconds (start-to-start, no overlapping SSH workers): DNS resolution,
  an independent bounded TCP preflight, SSH transport/KEX, pinned SSH server-key
  check, and `ssh-userauth` SERVICE_ACCEPT **without login**.
- Every 180 seconds when enabled: independent, directly routed 64 KiB HTTPS
  quality sample. This is not NPV tunnel throughput.
- When locally configured: DPT/2 over verified HTTPS with HMAC/ACK to the
  existing Core Collector. A 12-message FIFO buffer in RAM, durable per-request
  ACK checks, backoff and freshness logic remain unchanged.
- LED reflects Wi-Fi, the last fresh pre-auth SSH result and independent HTTPS
  warnings. A solid LED is NOT evidence that NPV authentication or tunneled
  application traffic works.
- No SSH credentials, no password attempts, no `direct-tcpip` channel, and no
  new server-side responder **when `PROBE_DEEP_ENABLED=0`**.

## Source-only refactor

- `SshProbe.h`: compile-time isolate experimental `DeepSshProbe.h`, user
  setting and authenticated SSH calls. No Deep dependency in normal build.
- `ProbeState.h`: make optional Deep LED gating compile-time; baseline LED
  precedence and future experimental behavior are preserved.
- `ssh_feasibility_main.cpp`: correct the misleading hardcoded
  `[dpt] version=1` Serial label to print the configured wire protocol.
- `tests/test_r1.cpp`: baseline verifies DPT/2 encodes TCP evidence without
  `z` (Deep field) and LED remains unaffected by dormant Deep state.
- No wire protocol, API endpoint, key format, timer, queue, TLS security,
  Core schema or bot semantics changed.

## Operator private config (NOT to commit)

`include/probe_private.h`:

```cpp
#define PROBE_EDGE_HOST "n1.nvlsup.com"
#define PROBE_EDGE_PORT 2252
#define PROBE_SSH_PIN_SHA256_HEX "<EXISTING_VERIFIED_64_HEX_PIN>"
#define PROBE_DEEP_ENABLED 0
```

Keep the already verified SSH host key pin; do not add SSH users or private
SSH keys for this mode. `include/telemetry_private.h` (also gitignored)
selects DPT/2 `PROBE_DPT_PROTOCOL_VERSION=2`, existing target ID `1`,
registered device/key IDs, a **fresh non-exposed** 64-hex HMAC secret,
the `/api/dpt/v2/telemetry` URL and the independently verified CA chain.
Do not copy any private key, HMAC secret or hotspot password into this document.

Windows PlatformIO: `pio run -e esp32dev_ssh_feasibility` and then (only
after review) `pio run -e esp32dev_ssh_feasibility -t upload --upload-port COM6`.
Read serial at 115200. Do not use the `esp32dev_r3_deep_compile` environment
for deployment; that environment exercises future experimental code only.

## Evidence and acceptance gates

1. Host tests: `python tests/run_host_tests.py`.
2. Firmware builds: `pio run -e esp32dev`,
   `pio run -e esp32dev_ssh_feasibility` and compile-only
   `pio run -e esp32dev_r3_deep_compile`. CI success alone is not field proof.
3. Real board: new boot + signed DPT/2 ACK, `dpt2_events` increasing,
   TCP/SSH stage evidence and fresh public HTTPS control. A successful
   unsigned v2 POST rejection (403) is just an endpoint/auth gate test.
4. Core classifier: D0 from eligible repeat TCP failures may be studied;
   **D1/D2/full HEALTHY require authenticated data-plane evidence** and
   must remain UNKNOWN/not measured while Deep is deferred. Do not enable
   bot alerts merely because Collector is reachable.
5. Keep `NVL_DENAPROBE_R3_ENABLED=0` until real-data and admin UX field
   acceptance. No hardware flash, server deployment, bot restart or secret
   provisioning is performed by this source refactor.

## Later, separately approved

`DeepSshProbe.h` remains in the repository for a future feasibility study,
without being required by today's monitor. Any authenticated data-plane
experiment needs a separately audited topology and dedicated authorization;
do not implicitly install account/responder services or touch customer SSH
identities as part of monitor-only deployment.
