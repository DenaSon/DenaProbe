# DenaProbe R1 — Relay-change A/B observation during user-reported degradation

**Observed date:** 2026-10-31 · **Time base:** Serial Monitor local UTC+03:30 (cross-checked against `[clock] epoch`)  
**Raw operator capture:** `device-monitor-261031-130149.log`, supplied excerpt 13:02:01–13:13:06  
**Operator interventions:** Existing route reportedly suffered connected-but-weak NPV user experience at observation start; a **new relay was activated at approximately 13:07**. Both descriptions come from the operator; there is no independent relay-state or client-app instrumentation in this Serial capture.  
**Platform:** ESP32 Wi-Fi connected to phone hotspot, `esp32dev_ssh_feasibility` isolated firmware; pinned SSH host key, no authentication.  
**Evidence status:** Meaningful counterexample to using SSH SERVICE_ACCEPT success as a reliable stand-in for user-perceived tunnel throughput. **Does not establish censorship, network cause, or relay efficacy.**

## Question and instrumentation limits

Compare the same probe **before** (~13:02–13:06:59) and **after**
(~13:07–13:13:06) the reported relay intervention. The times reflect
available observations, not proof of when network reconfiguration reached
the ESP32. Firmware tests an SSH entry hostname up through
`SERVICE_ACCEPT`, plus a separate public 64 KiB HTTPS **direct hotspot**
download. It cannot measure the actual NPV tunnel, NPV authentication,
SSH channel forwarding, sustained traffic throughput or clients' video
performance. It records `npv=NOT_TESTED`,
`throughput=NOT_TESTED`, `packet_loss=NOT_MEASURED` and
`filtering_verdict=INCONCLUSIVE`.

The operator's reported poor user experience **pre-switch is an external
observation**, not a direct firmware outcome. The operator has not supplied
a quantified NPV-client speed measurement, server route-change audit or
evidence that the ESP32's **tested SSH endpoint** changed along with the
customer relay. Do not automatically label this a verified A/B test of
the *same NPV data path*.

## Per-period comparison (derived from all 23 visible SSH results)

| Metric | Before relay, 13:02–13:06 | After activation, 13:07–13:13 |
| --- | ---: | ---: |
| SSH result count | 10 | 13 |
| `SERVICE_ACCEPT_PASS` | 10/10 (100%) | 11/13 (84.6%) |
| `SSH_TRANSPORT_TIMEOUT` | 0 | 1 |
| `SERVICE_ACCEPT_TIMEOUT` | 0 | 1 |
| Transport mean (all results, ms) | 3316.3 | 4629.1 |
| Transport median (all results, ms) | 3302 | 3337 |
| Transport minimum / maximum (ms) | 3273 / 3433 | 3289 / 12007 |
| Transport mean for PASS only (ms) | 3316.3 | 4080.2 |
| RSSI observed to hotspot (dBm) | -53 to -46 | -51 to -46 |
| Wi-Fi disconnected or host-key failure | none observed | none observed |
| New 64 KiB direct HTTPS samples | 2 | 2 |
| HTTPS outcomes | 1 PASS, 1 SLOW | 2 PASS |
| HTTPS body transfer (ms) | 3299, 4013 | 3167, 2947 |
| HTTPS body rate approx. (KiB/s) | 19, 15 | 20, 21 |
| Clock status | `ready=YES` | `ready=YES` |

**Do not average timeout values as though they were ordinary completed
handshakes.** The mean above includes the 12007 ms timeout observation;
median and distributions show that many post-intervention SSH sessions
still finished at the usual ~3.3 seconds. The 12-sample rolling
`[quality-window]` crosses the intervention and cannot serve as a
cleanly separated pre/post cohort.

## Exact noteworthy events and stage evidence

| Time | Probe sequence | Result and specific stage |
| --- | ---: | --- |
| 13:02:05–13:06:35 | 454–463 | **10 consecutive SSH PASS**, transport 3273–3433 ms, service 182–199 ms; operator reports weak NPV experience |
| 13:05:42 | 461 HTTPS | **SLOW**, 65536/65536, body 4013 ms, HTTP 200, TLS verification ON |
| ~13:07 | intervention | Operator activated new relay; **no corresponding relay-state event in probe log** |
| 13:07:08 | 464 | SSH PASS but transport **6055 ms**; observed SSH banner at **3195 ms** instead of baseline ~410–554 ms |
| 13:07:35 | 465 | SSH PASS, transport 3337 ms |
| 13:08:41 | 467 HTTPS | HTTP 200 PASS, body 3167 ms, ~20 KiB/s; endpoint is outside NPV |
| 13:09:13 | 468 | **SSH_TRANSPORT_TIMEOUT**, 12007 ms, no banner/KEX observed; DNS 1 ms, Wi-Fi RSSI -51 dBm; LED `SSH_FAILURE` |
| 13:09:38 | 469 | SSH PASS but transport **6146 ms**, banner observed after **3257 ms**; LED `SSH_READY` |
| 13:12:08 | 474 | SSH PASS, transport **6057 ms**, banner after **3178 ms** |
| 13:11:41 | 473 HTTPS | HTTP 200 PASS, body 2947 ms, ~21 KiB/s; this is before next service timeout |
| 13:12:43 | 475 | **SERVICE_ACCEPT_TIMEOUT** after `TRANSPORT_PASS=3289 ms` and `HOST_KEY_PASS`; waited **8004 ms** at service stage; LED `SSH_FAILURE` |
| 13:13:05 | 476 | SSH PASS again, transport 3295 ms, service 294 ms, LED `SSH_READY` |

### Stage-specific interpretation

The three post-switch **~6-second PASS** transports (seq 464, 469, 474)
had **~3.2-second banner-observation delays**, compared with
~0.4–0.55 seconds beforehand. The observed KEXINIT exchange gap and
subsequent KEX→NEWKEYS observation timing were roughly similar to
the baseline. The new delay is therefore strongly **associated with the
pre-banner portion** of the SSH transport measurement, though the probe
does not prove which underlying network/server mechanism caused it.
The first 12-second transport timeout has `stop_stage=
TCP_OR_SSH_BANNER_UNKNOWN`, and **no banner was observed**; it
must **not** be relabeled a confirmed TCP-connect failure or confirmed
blocking rule. The separate 8-second `SERVICE_ACCEPT_TIMEOUT`
occurred **after** transport and pinned host-key verification completed.

At the last reported window (seq 476, 13:13:05), `window=12/12 |
eligible=12 | pass=10 | network_failures=2 | wifi_lost=0 |
trust_failures=0 | ssh_latency_flag=PATH_FAILURES_OBSERVED`.
This 12-sample window overlaps **some earlier post-switch samples**
but excludes the pre-switch baseline: a valid current rolling snapshot,
not a cumulative outage count.

### Why direct HTTPS does not settle NPV quality

All four *new* measured direct-hotspot HTTPS requests obtained
HTTP 200 with TLS validation and 65536 bytes. The post-switch pair
was faster in this small sample. However, these checks hit a
**public Cloudflare test endpoint directly from Wi-Fi/hotspot** rather
than the relay, SSH channel, UDPGW or NPV data path. The changes
do **not** demonstrate the relay fixed customer throughput. Similarly,
the operator's real degradation pre-switch despite 10/10 SSH PASS is
evidence of a **visibility gap** in this experimental firmware, not
evidence the operator's report was incorrect.

## Working hypotheses and alternative causes

1. **Visibility mismatch:** SSH handshake success up through
   SERVICE_ACCEPT does not expose authenticated channel health,
   forwarding throughput, packet-loss patterns, app-level TCP or UDP
   forwarding, or client perceived latency. This alone can explain
   the reported healthy-looking pre-switch probe vs poor client experience.
2. **Route or endpoint mismatch:** The new relay may change the user
   traffic route but not the ESP32's tested edge host/port. Neither
   resolved endpoint IP nor relay ID is recorded in this excerpt.
3. **Transient post-change state:** Routing/DNS/cache convergence,
   SSH server backlog, server resource/load, or transient mobile network
   changes could yield timeouts or banner delays. No paired control
   or server-side trace distinguishes these hypotheses.
4. **Filtering:** remains a hypothesis from field reports, **not a
   proven cause**. Passing DNS or public HTTPS does not falsify
   selective filtering; SSH timeouts do not prove it.

## Next experiment (do not deploy risky firmware changes based only on this run)

Collect a **matched client + probe** comparison with a controlled
switch time and known endpoint identity:

1. Log exact local timestamp of the relay change, old/new **route ID**
   (or privacy-preserving identifiers), and whether the probe's
   destination IP/port actually changes. Do not publish private
   infrastructure or credentials.
2. From a separate phone/reference client on the same MCI mobile
   connection, record NPV app outcome **before, during and after**:
   authenticated tunnel readiness, browsing/connection latency,
   download/upload transfer rates, real application error counts
   and any UDPGW/channel forwarding results where available.
   Synchronize clocks; don't assume that connected status implies
   useful user data transfer.
3. Keep the ESP32's per-stage SSH result as an **independent indicator**
   with additional independent DNS, TCP/HTTPS controls at the incident
   timestamp. An old cached `https=PASS` is **not** a contemporaneous
   HTTPS measurement.
4. Repeat or extend each phase; include a stabilization period after
   route changes to separate transient convergence from persistent
   pathology. Use explicit sample windows, not mixed rolling counters.
5. Store exact timestamps with operator incident report and compare
   path-specific failure **rates**, pre-banner delays, post-transport
   service timeouts, and real-client transfer quality.
6. Any future telemetry should carry distinct signals:
   `SSH_PATH_PASS/FAIL`, `PUBLIC_HTTPS`, and
   `NPV_CLIENT_DATA_PATH` if independently instrumented. Never infer
   `VPN_HEALTHY` or `FILTERED` from the first two.

**Decision:** This is a strong R1 **scope-validation observation** and
a useful trace of two failure mechanisms, **not** a clean demonstration
that the relay caused or resolved filtering. Preserve the current code
and obtain route identity + matched NPV client evidence before
changing alert thresholds or releasing a filtering classifier.

**Source retention:** This document contains selected, non-sensitive
derived data from the user's 447-line local Serial capture. Keep the
unaltered raw capture privately for future correlation and review.
