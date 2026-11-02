# DenaProbe R3 Phase 2 — firmware source delivery and deferred hardware gate
**Date:** 2026-11-02 · **Stage:** source and CI only; hardware flashing and field E2E explicitly deferred by owner until all three phases are implemented.

## Implemented (feature gated)
- Existing `esp32dev` v0.0.4 default environment and legacy DPT/1 behavior preserved.
- Independent TCP preflight after DNS: `Result.tcp` measures connect success (code 1), budgeted timeout (code 20) or other socket failure (22); Wi-Fi loss yields local-unmeasurable (90). This is an independent fresh TCP socket, not inferred from libssh KEX, and never claims to identify censorship source.
- Optional restricted authenticated SSH after **pinned host key and verified SERVICE_ACCEPT**, using a dedicated locally supplied SSH private key and user, then `direct-tcpip` forwarding solely to `127.0.0.1:18180`. A relay-local bounded static TCP responder emits 0x5A bytes, allowing exact size and content verification without customer traffic. Two channels on **the same authenticated session**, separated by a configurable dwell (default 20s).
- Defaults: `PROBE_DEEP_ENABLED=0`; when explicitly enabled, 16KiB per transfer × 2, every 2 successful transport cycles. Configurable max 64KiB per transfer; controlled data budget (do not promise a 90s end-to-end alert until real observed cadence measured). No customer/root credentials, commands, VPN traffic or auto relay switching.
- Typed evidence: `TcpEvidence` and `DeepEvidence` with independently measured completion uptime, auth/session duration, transfer requested/received bytes and status.
- DPT/2 opt-in wire selection `PROBE_DPT_PROTOCOL_VERSION=2`: produces `c` and `z` nested fields (when measured), separate signing domain `DPT2`, HTTPS `/api/dpt/v2/telemetry`, v2 ACK checks, key ID must begin `v2-`. No v1->v2 key reuse. Wire `v=1` remains the default.
- New R3 compile-only PlatformIO environment `esp32dev_r3_deep_compile` makes the deep-auth/channel code build in CI while **not storing or provisioning secrets**. Host stubs and regression cases cover independent TCP, DPT/2 encoding and ACK.
- Invalid unprovisioned private key is **LOCAL_UNMEASURABLE**, not a filtering alert. TLS and SSH host key verification MUST remain enabled.

## Operational guardrails
- Private key is embedded in board firmware flash only after local manual provisioning and can be extracted by physical attackers; use restricted, disposable key and SSH account with `PermitOpen 127.0.0.1:18180`, deny interactive shell/PTY and administration. Never put real key in Git/CI/logs.
- Responders are started on relay loopback only after owner approval. Ensure responder expected bytes match `PROBE_DEEP_SAMPLE_BYTES`; no public listener.
- `tcp.code=20` uses a measured timeout budget, not definitive proof of where a packet was dropped; a TCP refusal vs network error cannot always be unambiguously distinguished by Arduino socket API.
- The deep witness tests SSH authentication and forwarding, not full NPV application success; its result is consumed by **server-only** probabilistic classification in Phase 3.
- No implicit healthy status when no deep result is present; mark NOT_MEASURED or UNKNOWN. During experimental enabling, deep session time can exceed the original 55s watchdog; guarded build expands the worker budget for this purpose.
- The DPT/2 endpoint must remain disabled by default on the server until all end-to-end gates completed.

## Source test and acceptance
1. Run `python tests/run_host_tests.py`, `pio run -e esp32dev`, `pio run -e esp32dev_ssh_feasibility`, `pio run -e esp32dev_r3_deep_compile`.
2. Run cryptographic cross-language DPT/2 HMAC golden vector and strict v2 ACK rejection of v1.
3. Run synthetic D0 and D1 evidence, serial FIFO, watchdog, missing Wi-Fi, invalid pin, insufficient heap, partial responder output and delayed second transfer.
4. **DEFERRED FIELD GATE after Phase 3:** restricted relay account and responder provisioned by operator; flash Board manually; confirm full SHA256 SSH host-key pin, auth, session/channel life, data-size check, Core accepted v2 ACK in SQLite, fresh HTTPS and stale/gap behavior; measure real heap, fragmentation, hotspot usage and latency. No claim that source CI certifies real VPN/NPV.
5. Stop and roll back independently on excessive memory, false D0/D1, queue gap or unauthorized key.

**Source implementation is not production activation.** If `libssh` authenticated forwarding is unstable on actual ESP32, leave feature OFF, report the gate blocked, and evaluate a separately approved alternative rather than inventing Data Plane PASS.
