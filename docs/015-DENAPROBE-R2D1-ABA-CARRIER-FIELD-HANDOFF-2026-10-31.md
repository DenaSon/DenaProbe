# DenaProbe — canonical firmware/hardware handoff and Rightel → MCI → Rightel field audit

**As of 2026-10-31; operator time zone: Asia/Tehran (UTC+03:30).**  
**Start here for the next conversation.** This is the latest *field-evidence handoff*, and supersedes the README's older "8 events / R2-C not started" status **only for DenaProbe**. Do not rewrite or erase the historical pre-hardening observations in [013](013-R2C-DPT1-HARDWARE-CORE-FIELD-VALIDATION-2026-10-31.md) or the R2-C design/regression record in [014](014-R2C-HARDENING-FIFO-LIVE-STATE-2026-10-31.md). Core/server counterpart: [NVLBot DenaProbe A/B/A handoff](https://github.com/DenaSon/nvl-bot/blob/feature/docs-denaprobe-aba-core-handoff-20261031/docs/DENAPROBE_R2D1_ABA_FIELD_ANALYSIS_HANDOFF_2026-10-31.md).

## 1. Purpose and what is actually being tested

- Target problem: a user reports **an unsuccessful SSH-Direct/NPV Tunnel connection on Hamrah-e Aval (MCI)** while the ESP32 continues to send DPT/1 signed telemetry and the Core collector stores it. The operator moved the board's hotspot from Rightel to MCI and back to Rightel to collect A/B/A comparisons.
- **ESP32 SSH probe ≠ customer SSH-Direct session:** on the board, `PROBE_EDGE_HOST` / `PROBE_EDGE_PORT` are configured privately for the **public Edge SSH entry** (field target port 2252). The operator describes difficulty connecting to the "Core" with the actual client; before correlating failures, independently verify client and board target IP, DNS, port, address family and whether an Edge/forwarder is involved. Do not assume they test identical paths.
- Firmware SSH evidence ends at authenticated pinned-host-key, SSH transport and **`SSH_MSG_SERVICE_ACCEPT`** (code `s=1`, `p=52`, observation bits `o=255` in the shown PASS samples). It does **not** log in, authenticate user credentials, open a `direct-tcpip` channel, establish SOCKS, or prove VPN application traffic.
- Independent public Cloudflare HTTPS sample (~64 KiB) and signed DPT telemetry HTTPS exercise **separate endpoints/channels** from SSH; HTTPS delivery succeeding while the real SSH tunnel fails is plausible. Wi-Fi RSSI is board↔hotspot RF, *not* MCI/Rightel cellular radio quality.
- Censorship/filtering, customer tunnel usability and ISP attribution are **not proven** by a single SSH PASS/FAIL or telemetry silence. Keep `LOCAL_UNMEASURABLE`, `STALE`, `PATH_FAILURE` and `TRUST_FAILURE` separate.

## 2. Hardware, firmware and protocol baseline

- Board: ESP32 DEVKITV1, Arduino + PlatformIO; Windows 10/VS Code, formerly COM6. **Phase 1 Wi-Fi via 2.4GHz mobile hotspot only. Do not introduce SIM800L 2G** until this phase is accepted.
- Active source work: [R2-A signed telemetry sender PR #6](https://github.com/DenaSon/DenaProbe/pull/6) (source branch `feature/r2a-dpt1-telemetry-sender-20261031`), [R2-C FIFO/urgent-ordered queue PR #7](https://github.com/DenaSon/DenaProbe/pull/7) (branch `feature/r2c-hardening-fifo-20261031`). Both were **open/unmerged** when this handoff was written. Earlier firmware release v0.0.4 is historical baseline, **not** proof of the current flashed firmware's exact Git SHA.
- Firmware: `src/ssh_feasibility_main.cpp`, `include/wifi_config.h`, ignored private `include/probe_private.h` and `include/telemetry_private.h`. Public templates should not enable the sender. Do not commit/reprint hotspot passwords, SSH account secrets, HMAC keys or private host pins.
- DPT/1 payload fields: `v,id,b,q,u,k,t,w,r,s,p,o,d,x,a` (optional `h`); BOOT (`k=3`), SSH PROBE_RESULT (`k=1`), DEVICE_EVENT (`k=2`). One numbered event per HMAC-authenticated HTTPS POST; durable ACK, local bounded journal and FIFO with retry. Code definitions are authoritative in [contract and registry](../contracts/dpt/v1/code-registry.json).
- For SSH `s=1` = `SERVICE_ACCEPT_PASS`; `s=30` = `SSH_TRANSPORT_TIMEOUT`; `s=50` = `SERVICE_ACCEPT_TIMEOUT`; stage `p=30` = `TCP_OR_SSH_BANNER_UNKNOWN`, `p=51` = `WAIT_SERVICE_ACCEPT`; `p=52` = `SERVICE_ACCEPT_RECEIVED`. Code `s=41` indicates pinned host-key mismatch and must not be reduced to generic filtering.
- Field sender/collector already demonstrated authenticated 200 ACK, isolated Core durable SQLite, and the baseline once showed `monitoring_gap=0`. Exact deployed/flashed source hashes and R2-C full adverse/soak acceptance **not independently attested** by the subsequent A/B/A log.

## 3. Operator-annotated carrier switch timeline

**Date: 2026-10-31, Iran local time.** Operator reports a switch from Rightel to MCI around **20:20** (UTC **16:50**) and an interrupted switch back to Rightel around **20:39** (UTC **17:09**). These times are *operator labels*, **not machine-attested SIM/operator telemetry**. The board cannot identify the phone's SIM operator from Wi-Fi.

Exclude two minutes on either side of switch boundaries for the primary comparison:

| Label | Iran local window | Interpretation |
| --- | --- | --- |
| RIGHTEL_BASELINE_2H | 18:18–20:18 | longer Rightel baseline (contains earlier backlogged/history-only events) |
| RIGHTEL_BEFORE_15M | 20:03–20:18 | clean Rightel pre-switch comparison |
| MCI_15M | 20:22–20:37 | clean approximate MCI comparison |
| RIGHTEL_AFTER_15M | 20:41–20:56 | Rightel after-switch comparison; **incomplete at observation time** |
| Transition-only | 20:18–20:22 and 20:37–20:41 | NOT for steady-state averages; preserve for link failures |

**Timestamp caution:** the read-only SQL script estimated probe measurement time as `received_at_ms - sender_age_ms`. `sender_age_ms` is measured sender-side queue latency from uptime; the resulting timestamp still includes network transfer/processing delay. It is approximate, not an exact UTC measurement time. Avoid hard operator cutoffs without transition buffers or independent clock/connection corroboration.

## 4. Verified Core extraction supplied by operator

Source: user-run read-only SQLite query of `/var/lib/denaprobe/telemetry.sqlite3` for `device_id=dp-mci-01`, last received **20:52:01** Iran local, **331 rows loaded** since 18:00. These are outcomes of the actual exported query, **not new measurements**.

| Metric | Rightel 2h 18:18–20:18 | Rightel pre 15m | MCI 15m | Rightel post 15m (partial) |
| --- | ---: | ---: | ---: | ---: |
| Stored events | 236 | 30 | 30 | 22 |
| SSH probe events | 234 | 30 | 30 | 22 |
| Eligible non-history SSH | 184 | 30 | 30 | 22 |
| SSH `SERVICE_ACCEPT_PASS` | 179 | 30 | 30 | 22 |
| SSH non-PASS | 5 | 0 | 0 | 0 |
| SSH PASS fraction of eligible | 97.3% | 100% | 100% | 100% |
| History-only records | 50 | 0 | 0 | 0 |
| DNS p50 / p95 (ms, PASS only) | 1 / 396 | 1 / 418 | 1 / 324 | 1 / 315 |
| Transport p50 / p95 (ms, PASS only) | 3327 / 5752 | 3345 / 5585 | 3356 / 4414 | 3318 / 3440 |
| Service Accept p50 / p95 (ms, PASS only) | 198 / 278 | **183 / 215** | **199 / 392** | **198 / 214** |
| Sender age p50 / p95 (ms) | 33193 / 65950 | 34851 / 62404 | 34848 / 62427 | 34843 / 64110 |
| HTTPS code PASS | 28 (plus 1 slow, 1 clock not ready) | 5 | 5 | 4 |
| HTTPS body p50 / p95 (ms) | 2628 / 2843 | 2585 / 2641 | 2830 / 3869 | 2624 / 3067 |

- **Main finding:** MCI completed **all 30/30** ESP32 probes to SSH `SERVICE_ACCEPT`, while the operator reports failures in the actual SSH Direct/NPV client. The missing diagnostic step is **post-Service-Accept authentication/channel/forwarding and/or exact path equivalence**, *not* evidence that TCP/SSH is universally blocked on MCI.
- **Second finding:** Service Accept P95 was 392ms MCI vs 215ms Rightel-before and 214ms Rightel-after, ~**82% larger** than Rightel-before. One MCI sample **20:28:55, seq #198** was PASS despite **1,398ms** Service Accept latency (transport 4,490ms). Around 12 of 30 MCI samples had `service_ms >= 300`. This suggests **more variable service-stage delay** in this short experiment; does not prove cause or broad ISP effect.
- Longer Rightel baseline had **five `s=50` `SERVICE_ACCEPT_TIMEOUT` at stage 51**, even before switching, and **50 history-only** samples. Thus *MCI is not the only interval with historical anomalies*. Zero interior sequence gaps and history-only >0 can coexist: these are different properties.
- Switch transition: **20:40:31, seq #221, `s=30` `SSH_TRANSPORT_TIMEOUT`, `p=30`, `o=0`, transport=12007ms**. Then **20:40:54, seq #222, PASS**. This isolated timeout coincides with the operator-reported switch back; it is a transitional event and not proof of persistent Rightel failure or intentional blocking.
- HTTPS samples in the clean MCI interval passed, **5/5**; this confirms the board could perform those independent HTTPS samples, not that its NPV tunnel worked.
- The original ad-hoc comparison script reported Wi-Fi RSSI p50/p95 as `None` because its percentile helper discarded negative dBm values. This is a **report script filtering bug**, not proof RSSI was missing or cellular quality unknown. Correct RSSI calculations must allow negative dBm values and label them **Wi-Fi only**.
- Small samples and 15-minute windows mean descriptive evidence, not statistically definitive claims.

## 5. Key conclusion and the next controlled experiment

### Current hypothesis, not a verdict

The ESP32 has demonstrated **SSH pre-auth path viability to its configured public Edge entry** under both carriers, but did not reproduce the operator's real SSH Direct session failure on MCI. Focus on identifying **where the real client diverges from the probe**:

1. **Exact endpoint audit:** Compare client destination hostname, resolved A/AAAA, IPv4-vs-IPv6, effective port, DNS, Cloudflare/Edge path, SSH server version, username/credentials and client features without disclosing secrets. The board currently uses an IPv4-public-Edge path; Windows tests should use `ssh -4` initially.
2. **Windows 10 OpenSSH (installed, per operator):** run `ssh -4 -vvv -E "$env:USERPROFILE\Desktop\ssh-mci.log" -p 2252 -o ConnectTimeout=12 -o ConnectionAttempts=1 TESTUSER@PUBLIC_EDGE_HOST` on direct MCI hotspot, VPN/proxy off; repeat identically on Rightel. `TESTUSER@PUBLIC_EDGE_HOST` is an example, not verified account/host. Verify first-use host-key fingerprint against a trusted pin; redact username/IP and all credentials before sharing.
3. Identify last progress: TCP, SSH banner, KEX/NEWKEYS, user authentication, open session/channel. No OpenSSH debug log has yet been supplied as of this handoff; **do not claim a stage of failure**.
4. If authentication succeeds, optionally test `ssh -N -D 127.0.0.1:1080` with a **disposable authorized** SSH account and `curl.exe --socks5-hostname` to verify actual forwarding. `-D` is a client-side SOCKS proxy, not proof of NPV's exact proprietary behavior; account/server forwarding must be permitted.
5. Only if the actual failure is demonstrably post-`SERVICE_ACCEPT`, design an opt-in **future ESP32 probe** for controlled userauth/channel testing with disposable, least-privilege test credentials and new documented secret-handling/recovery; **DO NOT** change DPT/1 wire semantics or introduce real customer credentials to firmware by default. Do not implement before real-client audit and review.
6. Run R2-D2 adverse-network/queue/reboot/timeout tests, R2-D3 >=24h independent field soak, and only later consider R2-E server incident engine with corroboration/cooldown. No automatic network action or Telegram incident notifications now.

## 6. Code and operational state / guardrails

- **Firmware:** R2-C source PR #7 remains open/unmerged at documentation inspection. Earlier signed sender ACK on real board and prolonged telemetry are operator-confirmed; exact flashed binary/SHA and full R2-C acceptance not proven merely from continued samples.
- **Core:** collector is separate `denaprobe-collector.service` on loopback 127.0.0.1:18081, signed DPT/1 HTTPS through Cloudflare, SQLite `/var/lib/denaprobe/telemetry.sqlite3`. No public read endpoint, no collector → customer bot DB writes. The NVLBot DenaProbe dashboard source and operator-view screenshot are documented in its repo; dashboard polish's live release is not independently verified.
- **Do not:** alter production NPV/GOST/WG/DNS/Cloudflare route/customer connections, restart collector to analyze history, expose `devices.json`/HMAC secrets, assume `k1` revocation (must verify private-key registry safely), merge source without CI review, or equate a GitHub merge with flash/deploy.
- **Use source-of-truth statuses:** [R2-C firmware PR #7](https://github.com/DenaSon/DenaProbe/pull/7); [Core R2-C PR #263](https://github.com/DenaSon/nvl-bot/pull/263); [Metrics/dashboard #264](https://github.com/DenaSon/nvl-bot/pull/264); [UI guide #265](https://github.com/DenaSon/nvl-bot/pull/265). At handoff inspection all were **open**.

## 7. Copy/paste next-chat handoff

> Continue DenaProbe, not DenaGate. Review canonical hardware document `docs/015-DENAPROBE-R2D1-ABA-CARRIER-FIELD-HANDOFF-2026-10-31.md` in `DenaSon/DenaProbe` and paired `docs/DENAPROBE_R2D1_ABA_FIELD_ANALYSIS_HANDOFF_2026-10-31.md` in `DenaSon/nvl-bot`, plus PRs #7 / #263 / #264 / #265. Real A/B/A Iran local: Rightel before 20:20, MCI ~20:20–20:39, Rightel after ~20:39. Clean 15m runs: SSH SERVICE_ACCEPT PASS 30/30, 30/30, 22/22 (last partial), while actual NPV SSH Direct on MCI failed per operator. MCI Service P95 392ms vs 215/214 Rightel; seq221 transient transport timeout 20:40:31 on switch back. SSH probe does not test authentication/channel or necessarily the same Core/Edge destination as NPV. Windows 10 OpenSSH is installed; next obtain scrubbed `ssh -4 -vvv` log over MCI, then Rightel, compare exact endpoint and stage; only then consider post-auth test. No unapproved flash/deploy/merge/production routing change. Keep evidence vs hypothesis explicit.
