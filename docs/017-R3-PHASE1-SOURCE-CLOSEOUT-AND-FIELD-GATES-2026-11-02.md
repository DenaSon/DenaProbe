# R3 Phase 1 — ESP32 source closeout and physical acceptance gates
**Date:** 2026-11-02. **Scope:** R2-A DPT/1 + R2-C FIFO and telemetry resilience. **NOT an R3 Phase 2 data-plane release.**
**Status:** source fixes prepared in `feature/r2c-hardening-fifo-20261031`; GitHub checks/merge must be confirmed against exact final commits; **no production flash claimed**.

## Reviewed change set
- Existing R2-A telemetry remains opt-in: HMAC SHA256, private `telemetry_private.h`, pinned TLS CA, immutable per-boot payloads, exact signed ACK and volatile queue of 12 records; `esp32dev` legacy default remains unchanged.
- Strict FIFO chosen by `Journal::choose()`. Urgent results initiate early draining but never jump older `q`. If the queue overflows, record gap and retain pending BOOT. Do not claim delivery of evicted records.
- Worker timestamps: refresh extended `millis()` *after consuming a completed worker event*; avoid interpreting an event that completed after a loop snapshot as a 2^32-ms-old observation.
- Sender startup: SNTP/TLS clock must initialize whenever DPT sender **OR** public HTTPS quality probe needs it. Turning off `PROBE_HTTPS_QUALITY_ENABLED` must not disable the authenticated sender.
- A BOOT event is never discarded on retry-budget exhaustion: use capped backoff (160s plus jitter, or longer server Retry-After) to keep the only registration marker. On an authenticated `HISTORY_ONLY` ACK for an expired BOOT, restart device **once at that point** to establish a new fresh boot ID/sequence; while still offline do not reboot-loop. On a permanent BOOT REJECT, pause sender rather than sending unregistered probe events. The restart necessarily loses volatile queued records; those records must **never** be presented as delivered.
- Local resource, Wi-Fi-loss and host-key errors remain distinct from network-path failures; no VPN-login or censorship verdict.

## Required checks before live declaration
1. CI on final source HEAD: `python tests/run_host_tests.py` including FIFO, HMAC/ACK and extended uptime regressions; `pio run -e esp32dev` and `pio run -e esp32dev_ssh_feasibility`.
2. Pair with the independently staged Core Collector at a reviewed SHA; verify signed POST ACK, fresh `BOOT q=1`, q=2..n strictly ordered and latest `monitoring_gap=0` **only after two eligible SSH samples**; verify `https_sequence` only on a fresh HTTP sample.
3. Send with public HTTPS quality disabled in a *controlled* test build: SNTP must still start and signed DPT BOOT must receive ACK; keep TLS verification ON.
4. Simulate delayed worker completion near sampling tick and `millis()` overflow. Event age must remain measured within valid unsigned extended uptime, not billions of seconds old.
5. Simulate sender downtime > `BOOT_MAX_AGE_MS`, then recovery: BOOT must be retained through retries; a historical ACK must lead to a new boot lifecycle without a reboot storm while disconnected.
6. Test 429/5xx, ACK drop, >12 queued events, Wi-Fi down/reconnect, HMAC tamper, revoked key, low heap, queue full and ongoing telemetry with no probe worker overlap.
7. Run 24h physical endurance if practical; log actual board commit, serial/ACK sequence, heap, queue dropped counter and Core db state. Do not assert 90s alerts: there is no classifier yet.

## Safe operator-run field sequence
**Core first:** (a) read-only inspect `systemctl status denaprobe-collector` and `sha256sum` of `/opt/nvl-dpt-collector/denaprobe_ingest/collector.py`, (b) isolated staging checkout+standalone tests, (c) nonsecret key-ID-only check: revoked `k1`, active `k2`, (d) online SQLite backup into root-restricted path, (e) update **only** the isolated Collector with a file backup+rollback, (f) verify loopback/public health 200, unsigned POST 403 and signed board ACK 200. Never restart NVLBot/GOST or edit active DNS/Edge.
**ESP32 next:** Windows VSCode + PlatformIO on matching source commit, ignored device keys and SHA256 SSH host-key pin, `pio run -e esp32dev_ssh_feasibility`, `pio run -e esp32dev_ssh_feasibility -t upload`, `pio device monitor -b 115200 -f time -f log2file`. Compare new boot q and Core last-state read; the board flash is a **manual physical action**, not performed by GitHub.
**Rollback:** on Core restore only prior isolated Collector file, restart only `denaprobe-collector` and retain SQLite/keys; on ESP32 deliberately flash previous known-good firmware. Validate after rollback.
**Stop if:** missing expected key rotation, unexpected target revision, unknown/invalid HMAC result, duplicate/ordering regression, failed CI, no full backup or user-approval to touch running Core/physical board.
**Explicit exit status:** Code-review/CI signoff != live field acceptance. R3 Phase 2/3 remain OFF.
