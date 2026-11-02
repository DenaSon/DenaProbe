# R2-C — DPT/1 ESP32 ↔ Core field validation (before hardening)

**Observed:** 2026-10-31 · **Scope:** real hardware/isolated Collector field evidence.  
**Firmware source:** `DenaSon/DenaProbe`, `feature/r2a-dpt1-telemetry-sender-20261031`, PR #6 (open/unmerged at documentation time).  
**Collector source:** `DenaSon/nvl-bot`, `feature/dpt-r2b-core-collector-20261031`, PR #262 (open/unmerged at documentation time).  
**Status:** **transport, signed ingestion, durable storage and ACK: PASS**; **live-state continuity: OPEN**. This document freezes observations **before R2-C Hardening**. No hardening implementation, bot alerts, classification or production acceptance is claimed.

## Evidence levels and scope

- **Operator-verified on Core and Windows:** public Cloudflare Tunnel route to a real local collector; external 200 health response and 403 unsigned-POST rejection; systemd enabled/active; SQLite records, integrity check and latest-state query.
- **Operator-verified on physical ESP32:** successful PlatformIO build/upload, `[dpt] READY`, SNTP eventually `ready=YES`, actual HMAC-authenticated HTTPS POST with matching HTTP 200 ACK, SSH and independent public HTTPS measurements.
- **Source-reviewed:** queue discipline, live-state acceptance and historical gating explain the observed out-of-order behavior.
- **Not verified:** k1 revocation (the operator was instructed to revoke, but its actual completion was not evidenced); exact duplicate/replay/tamper tests on live public path, 429/5xx/reboot recovery, 24-hour endurance, adverse-network cases, retained-history policy, VPN/NPV application health and production alert behavior.

Do not publish raw private keys, `devices.json`, `include/telemetry_private.h`, hotspot credentials or service IPs. The initially provisioned `k1` HMAC key appeared in conversation text and must be treated as compromised. A different `k2` was subsequently used successfully on hardware; this alone does **not** verify `k1` revocation.

## Architecture verified

```text
ESP32 DevKitV1 (MCI LTE hotspot via 2.4GHz Wi-Fi)
  SSH pre-auth probe: public Edge n1.nvlsup.com:2252
  independent 64KiB HTTPS probe: Cloudflare speed test
  DPT/1 signed HTTPS: POST https://board.nvlsup.online/api/dpt/v1/telemetry
                        |
                 Cloudflare HTTPS
                        |
             denaprobe-core Tunnel
                        |
           http://127.0.0.1:18081
                        |
       denaprobe-collector.service (nonroot)
                        |
     /var/lib/denaprobe/telemetry.sqlite3
     /var/lib/denaprobe/devices.json (0600)
```

The Core's existing GOST listener on 443, production NVLBot and `/root/master_bot.db` are not part of the Collector path and were not changed by these steps. The old temporary `denaprobe-healthz` origin at `127.0.0.1:18080` was preserved as a routing rollback option. The Cloudflare *published application route*, **not** global Zero Trust mesh/CIDR routes, was changed to 18081. The public hostname remains `board.nvlsup.online`.

## R2-B Core installation and Cloudflare cutover — observed PASS

- A separate staging checkout `/root/nvl-dpt-r2b-stage` was pinned to source commit `7386ac3b0ab306ef772273bd74fb33f4385d75c4`.
- On Core: `python3 -m unittest discover -s tests -p 'test_denaprobe_collector.py' -v` passed **10/10**; `python3 -m py_compile denaprobe_ingest/collector.py` passed.
- Nonroot user `denaprobe`, collector at `/opt/nvl-dpt-collector/denaprobe_ingest/collector.py`, dedicated SQLite, target `id=1` -> `n1.nvlsup.com:2252` (`TARGET_REVISION=1`).
- `systemctl is-enabled denaprobe-collector` -> `enabled`; `systemctl is-active denaprobe-collector` -> `active`; `ss -lntp` showed **127.0.0.1:18081 only** (not public `0.0.0.0`).
- Public Windows `curl.exe -i https://board.nvlsup.online/healthz` -> **HTTP 200**, `{"status":"ok","service":"denaprobe-core"}`.
- Public unsigned `POST /api/dpt/v1/telemetry` with `{}` -> **HTTP 403**, `{"error":"request_rejected"}`. This demonstrates the auth gate, not live signed delivery by itself.
- `runuser -u denaprobe -- python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py check` initially returned `DPT_CHECK= ok EVENT_COUNT= 0`; `recent --limit 20` initially empty.
- Cloudflare Tunnel connector `denaprobe-core` was reported Healthy. Public HTTPS and the local response signature verified the cutover in the user-run checks.

## Device provisioning, TLS and local config

- Registered `DEVICE=dp-mci-01`, target `1`, initially `KEY_ID=k1`; after disclosure of the original secret, the operator was instructed to revoke k1 and provision `KEY_ID=k2`, saving the new secret privately on the operator's PC.
- Successful hardware signed delivery establishes that an accepted secret/key combination was active, consistent with `k2`; **do not conclude the old key is revoked until checked**.
- Public certificate for `nvlsup.online` was observed with issuer `Google Trust Services WE1`, valid 2026-10-28 through 2027-01-26. `openssl s_client -showcerts` reported the `WE1 -> GTS Root R4 -> GlobalSign Root CA` chain. The board CA configured as the Google Trust Services `GTS Root R4` PEM **raw C++ string literal**; no `setInsecure()`.
- Only the ignored `include/telemetry_private.h` contains board secrets. The public `include/telemetry_private.h.example` is deliberately disabled by default. Required settings after operator-controlled provisioning:

```cpp
#define PROBE_DPT_ENABLED 1
#define PROBE_DPT_OFFLINE_SMOKE_TEST 0
#define PROBE_DPT_DEVICE_ID "dp-mci-01"
#define PROBE_DPT_TARGET_ID 1
#define PROBE_DPT_KEY_ID "k2"
#define PROBE_DPT_SECRET_HEX "<64 lowercase hex digits, private>"
#define PROBE_DPT_API_URL "https://board.nvlsup.online/api/dpt/v1/telemetry"
#define PROBE_DPT_CA_PEM R"PEM(-----BEGIN CERTIFICATE-----
<verified GTS Root R4 public PEM>
-----END CERTIFICATE-----
)PEM"
```

- Build/upload environment: `esp32dev_ssh_feasibility`, physical `COM6`, Windows PowerShell/VS Code with PlatformIO. The observed build completed `SUCCESS` and new firmware boot printed `[dpt] READY | version=1 | mode=HTTPS_SENDER | queue_capacity=12 | period_ms=90000`. IntelliSense `C/C++(1696)` warning on a private header is not evidence of a compiler error; PlatformIO build was the authoritative check.
- Earlier hardware run had `CLOCK_NOT_READY` with epoch near boot uptime. On the field run SNTP began after Wi-Fi/IPv4; around boot `40,781ms` `epoch=1793457358 | ready=YES`. DNS resolution of NTP hosts was observed, but direct UDP/123 proof remains **unverified**. HTTPS speed sample then passed with TLS verification enabled.

## Real R2-C E2E evidence — observed PASS (transport only)

Hardware serial log (operator local time, 2026-10-31):
- `18:05:19`: `[dpt] READY | version=1 | mode=HTTPS_SENDER | queue_capacity=12 | period_ms=90000`.
- `18:05:58`: `[clock] ... epoch=1793457358 | ready=YES`.
- `18:06:19`: independent 64 KiB public HTTPS probe `PASS`, HTTP 200, 5,337ms; it does **not** measure the VPN.
- `18:06:22`: `[dpt-send] seq=1 | outcome=ACCEPTED | http=200` (BOOT).
- `18:06:47`: seq=2 `ACCEPTED`, HTTP 200.
- `18:06:51` and `18:06:54`: seq=5 and seq=4 `HISTORY_ONLY`, HTTP 200.
- `18:07:17`: seq=6 `ACCEPTED`, HTTP 200.
- `18:07:19`: seq=3 `HISTORY_ONLY`, HTTP 200.
- `18:08:22` and `18:08:24`: seq=8 and seq=7 `HISTORY_ONLY`, HTTP 200.
- Repeated SSH transport/pinned host key/`SERVICE_ACCEPT_PASS` observations; successful pre-auth SSH is **not** authenticated VPN or a filtering verdict.

Core:
- `DPT_CHECK= ok EVENT_COUNT= 8` after sender activation.
- `recent --limit 20` listed 8 persisted events with the same `device_id=dp-mci-01` and boot identity, event kind `3` BOOT, `2` local event and `1` result, including 5 `history_only=1` rows.
- Authenticated delivery, TLS and ACK matching therefore **passed on hardware**, while full protocol regression and live-state correctness **did not**.
- A later **read-only** `device_latest_state` query showed `ssh_sequence=12`, `https_sequence=NULL`, `last_event_sequence=12`, `monitoring_gap=1`. This is a **later snapshot** than the 8-event `check`; do not combine those counts as one atomic state.

## Open finding — not yet fixed (R2-C Hardening entry gate)

**Finding:** The firmware's `Journal::choose()` deliberately prioritizes newest backlog observations/urgent results after BOOT, whereas the Collector promotes a result into live-state only when `q == previous_max_sequence+1`, on the current registered boot, with fresh, recognized, authorized target data. Out-of-order signed records are preserved historically and ACKed `r=2`. This explains observed history-only sequences and the still-open `monitoring_gap=1`. The `https_sequence=NULL` additionally shows that a live HTTPS observation has **not yet been accepted into latest state**, despite HTTPS samples recorded historically.

**This is not a Collector outage nor a reason to disable security checks.** Preserve historical records and strict ACK/HMAC/idempotency validation. A future, separately scoped **R2-C Hardening** change should reconcile FIFO/urgent dispatch, bounded retries/overflow, ordering with correct gap recovery, and source+collector regression tests. Do not silently mark continuity successful or treat a pre-auth SSH PASS as a customer VPN PASS.

**Acceptance gates for later work:** demonstrate ordered durable accepts including a fresh HTTPS-bearing result in latest state, `monitoring_gap=0` after continuous healthy sequence, restart/new BOOT semantics, deliberate packet loss/overflows, duplicate exact-body ACK (`r=1`), tamper/identity conflict (`409`), 429/5xx retry, and sustained heap/task health. Recheck targeted negative SSH/HTTPS faults. **No alert job, Telegram notification, automatic route or GOST change** until those gates and explicit operator signoff.

## Safe read-only verification commands (Core)

```bash
runuser -u denaprobe -- python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py check
runuser -u denaprobe -- python3 /opt/nvl-dpt-collector/denaprobe_ingest/collector.py recent --limit 20
runuser -u denaprobe -- python3 - <<'PY'
import sqlite3
db = sqlite3.connect("file:/var/lib/denaprobe/telemetry.sqlite3?mode=ro", uri=True)
db.row_factory = sqlite3.Row
for row in db.execute("""SELECT device_id,ssh_sequence,https_sequence,
                                last_event_sequence,monitoring_gap
                         FROM device_latest_state"""):
    print(dict(row))
db.close()
PY
```

For the exposed `k1`, confirm **only key IDs**, never print key values:

```bash
runuser -u denaprobe -- python3 - <<'PY'
import json
from pathlib import Path
p = Path("/var/lib/denaprobe/devices.json")
entry = json.loads(p.read_text())["devices"].get("dp-mci-01", {})
keys = entry.get("keys", {})
print("device_enabled=", entry.get("enabled"))
print("k1_revoked=", "k1" not in keys)
print("k2_present=", "k2" in keys)
PY
```

If k1 remains, revoke it with the service's `revoke --id dp-mci-01 --key-id k1` CLI. Do not delete/recreate SQLite or re-provision an existing key ID. Keep the local secret in an ignored private config and restrict copied temporary TXT files.

## Rollback / operational fences

To roll back only telemetry ingress, re-point the **existing** Cloudflare Tunnel published application origin from `http://127.0.0.1:18081` to `http://127.0.0.1:18080` (if the temporary healthz origin still exists), and stop `denaprobe-collector` only after validating rollback. Retain DB/device registry as evidence, and keep production `gost.service`, `nvlbot.service`, protected 443 and bot DB untouched. If telemetry ingress is unavailable for an extended period, disable only the DPT firmware sender in a new flash; the SSH/HTTPS probes remain independent.

**Release gate:** R2-C transport smoke = **PASS**; R2-C full live-state/regression = **OPEN**; R2-C Hardening = **NOT STARTED**. No merges or production cutover implied by this field report.
