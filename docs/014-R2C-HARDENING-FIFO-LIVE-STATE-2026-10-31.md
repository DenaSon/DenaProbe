# R2-C Hardening — ordered sender and verified live-state continuity

**Date:** 2026-10-31  
**Change branches:** DenaProbe `feature/r2c-hardening-fifo-20261031` (base: R2-A PR #6); NVLBot `feature/r2c-hardening-live-state-20261031` (base: R2-B PR #262).  
**Phase:** implementation + regression source review, **NOT deployed, NOT field-approved**. Historical real-world evidence remains frozen in [013-R2C field report](013-R2C-DPT1-HARDWARE-CORE-FIELD-VALIDATION-2026-10-31.md).

## Root cause from actual 2026-10-31 field data

- Core verified 8 initial events, later `ssh_sequence=12`, `https_sequence=NULL`, `monitoring_gap=1`.
- Original `Journal::choose()` picked urgent events first, then the newest queued sample, allowing `q=6` to be accepted before historical `q=3/4/5`. The collector preserved the older records as `HISTORY_ONLY`; a fresh HTTPS-bearing `q=3` could not advance the HTTPS live channel.
- The Collector's old `last_event_sequence=q-1` continuity check could also count a preceding BOOT / DEVICE_EVENT as the first corroborating **probe**, which would clear the monitoring gap after only one SSH observation.

## Changes implemented (source only)

1. **Firmware FIFO:** `Journal::choose()` returns the oldest retained item. BOOT remains first, including when an unsent BOOT is pinned during overflow. ACK removal continues to require an exact signed/matching `v,b,q`.
2. **Urgent trigger without overtaking:** `Journal::hasUrgent()` starts draining at once (subject to existing Wi-Fi, SNTP/TLS, memory and probe-worker serialization gates), but sends older pending messages first. Offline smoke mirrors the actual order. This favors correctness over bypassing a backlog: urgent fault reporting can be delayed behind earlier events.
3. **Overflow preserved as evidence gap:** bounded RAM queue and deterministic oldest-non-BOOT eviction unchanged; no relabeling `q`, no fabricated PASS or payload rewrite. Lost event sequences remain absent and the backend must mark `MONITORING_GAP`. After fresh newer consecutive probes, it may recover live confidence.
4. **Collector corroboration:** advance a fresh/ordered authorized SSH observation as before, but only clear `monitoring_gap` when the immediately preceding **eligible SSH result** is the previous `q` and arrived within the SSH freshness interval. BOOT, local link events and history-only samples **cannot** establish two-probe continuity. HTTPS live state updates only on an accepted fresh result that actually includes `h`; missing `h` never overwrites the prior sample.

No DPT/1 wire-field/registry/ACK change. No permission reduction, no unauthenticated administrative read endpoint, no change to HMAC, certificate validation, original immutable body or 1KiB limit. No Telegram alert classifier or GOST/NPV auto-action.

## Host regressions added

**ESP32** `tests/test_r1.cpp`:
- BOOT, healthy results and an urgent failure are sent in strict sequence FIFO.
- A local urgent event triggers draining without bypassing earlier healthy events.
- Oldest non-BOOT overflow policy retains BOOT, counts seven dropped samples, and preserves non-contiguous survivor sequence IDs (no relabeling).
- A duplicate ACK (`r=1`) only validates for the exact event identity.
- Existing HMAC vector, ACK rejection, TLS/SSH host tests remain included.

**Core** `tests/test_denaprobe_collector.py`:
- A Wi-Fi event after BOOT cannot count as an SSH sample; the first accepted SSH/HTTPS result retains a gap, the next sequential SSH clears it and preserves last fresh HTTPS.
- Delayed/out-of-order history-only events cannot advance live; following two ordered fresh SSH results restore confidence.
- An old server-side previous SSH arrival does not count as current corroboration.
- Existing HMAC, duplicate, tamper 409, 403 unsigned, boot replay, version/schema and SQLite integrity tests remain included.

## CI checks / deployment order

```bash
# DenaProbe local Windows (after checkout of hardening branch)
python tests/run_host_tests.py
pio run -e esp32dev
pio run -e esp32dev_ssh_feasibility

# Core isolated checkout for Collector only (never replace running live files blindly)
python3 -m unittest discover -s tests -p 'test_denaprobe_collector.py' -v
python3 -m py_compile denaprobe_ingest/collector.py
```

**Release order:** CI review -> stage updated Collector in an independent checkout and run all tests -> backup live SQLite using online backup API -> compare service config and private key registry before changing code -> operator-controlled update of **isolated** Collector with rollback file available -> verify local 200/403 and public health/auth gate -> compile/flash hardening ESP32 from its own branch with ignored local `telemetry_private.h` -> capture a **new boot ID** (new flash resets board) -> observe ordered q 1, 2, 3, 4... and fresh HTTPS live sample -> inspect latest state in read-only Core DB.

Do not restart production `nvlbot.service` or `gost.service`, touch `/root/master_bot.db`, change tunnel/DNS, print `devices.json` contents, or weaken TLS. First verify that the exposed old `k1` key is revoked without displaying private values; `k2` must be present. Existing live Collector and flashed firmware are **not** automatically updated by GitHub commits.

## Field acceptance (not yet met)

- [ ] PR CI green for both repos (host + firmware CI).
- [ ] No private key leakage; `k1` revoked and `k2` retained.
- [ ] New boot `q=1` ACK 0; subsequent `q` sequence accepted in order.
- [ ] `ssh_sequence` increases and `monitoring_gap=0` only after two fresh, consecutive SSH results, not a BOOT/link event.
- [ ] New fresh HTTPS-bearing SSH `h.c=1` or `h.c=2` advances `https_sequence` and stays cached (not re-stamped) on non-HTTPS samples.
- [ ] Delayed/out-of-order/older-boot samples remain history-only and do not trigger actionable incidents.
- [ ] Force queue overflow, retries/429/5xx, lost ACK/idempotent duplicate, reboot/key rotation and expiry in controlled environment without corrupting SQLite or claiming false VPN state.
- [ ] Sustained memory/task stability; appropriate release/rollback signoff.
- [ ] No bot alert/automatic network change before these gates.

**Rollback:** restore previous tested isolated Collector file, restart **only** `denaprobe-collector` and verify public 200/403; revert firmware by a deliberate build/flash if needed. Do not drop existing DB, revoke the good k2 key or silently suppress evidence.
