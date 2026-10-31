# DenaProbe R1 — ESP32 Field Evidence: Wi-Fi and Mobile-Data Outages

**Date:** 2026-10-30 (serial-console local timestamps, UTC+03:30)  
**Target:** `esp32dev_ssh_feasibility`, ESP32 DevKit / internal Wi-Fi on an MCI/LTE phone hotspot  
**Baseline:** GitHub `master` after R1 SNTP/LED PR #4, as observed in owner-provided Serial logs  
**Status:** Wi-Fi outage detection and automatic reconnection **PASS**; mobile-data-off DNS failure detection **PASS**; mobile-data restoration **NOT YET EVIDENCED**; real filtering/NPV validation **PENDING**

This document records observations supplied by the hardware operator, not a
reproduction in CI. The complete raw Serial captures are intentionally **not**
committed to the public repository. Time values are the PC Serial Monitor's
timestamp labels; device epoch and `boot_ms` are independently reported.
A fresh successful SSH transport / host-key / SERVICE_ACCEPT sequence proves
only those stages, **not** SSH authentication, NPV data transfer or a carrier
filtering verdict. The probe does not inspect the LTE radio signal.

## 0 — Baseline and known constraints

- R1 runs isolated SSH transport + pinned SHA-256 host-key + SERVICE_ACCEPT,
  without login; direct public HTTPS is a separate **non-VPN** 64 KiB sample.
- SSH interval ~30 seconds; scheduled HTTPS interval ~180 seconds after clock
  readiness. `[quality-window]` contains at most the last 12 SSH samples.
- LED GPIO2 priority: Wi-Fi down = slow blink; fresh SSH failure = two short
  flashes; fresh SSH pass and HTTPS unmeasured = solid; HTTPS slow = long
  ON/short OFF; fresh HTTPS endpoint failure = triple flashes.
- Initial healthy hardware runs reached `12/12` SSH path PASS, and direct
  HTTPS samples verified CA, returned HTTP 200, and downloaded 65536 bytes.
  A slow HTTPS sample is a small transfer observation, not a full-network
  speed test.
- Fresh reboot is **verified** at 22:39:00 by `POWERON_RESET` and the
  subsequent SSH `seq=1`; initial connection at 22:39:23 and first SSH
  PASS at 22:39:28. After SNTP started 22:39:23, clock first reported
  `ready=YES` at 22:45:10 (about 5m47s after SNTP initialization).
  Earlier runs synced much faster: this variability is an **open diagnostic**.
  DNS success for NTP names does not test UDP/123, and `udp123=UNVERIFIED`.

## 1 — Controlled Wi-Fi hotspot OFF / ON

**Operator action:** The phone hotspot was disabled at approximately 22:48
(operator estimate); later reenabled around 22:50. The firmware's observed
link-down and link-up timestamps are authoritative for the probe.

| Evidence | Serial time | Observation |
| --- | --- | --- |
| Link-down detected | 22:49:06 | `[quality-link] wifi=DOWN`; clock state `LINK_DOWN_OR_NO_IP` |
| LED on link-down | 22:49:06 | `[led-state] mode=WIFI_DOWN` |
| Reconnect attempts | 22:49:06–22:51:06 | `[wifi] CONNECTING` approximately every 20s |
| Link-up detected | 22:51:08 | `[quality-link] wifi=UP` |
| SNTP restarted after IP | 22:51:08 | `after_ipv4=1`; both NTP-host DNS resolutions PASS |
| First SSH after link-up | 22:51:12 | `SERVICE_ACCEPT_PASS`, `transport_ms=3653` |
| LED recovered | 22:51:12 | `mode=SSH_READY` (solid, absent HTTPS warning) |
| Wi-Fi outage counter | 22:51:12 | `wifi_down_events_since_boot=1` |
| HTTPS after recovery | 22:51:58 | `PASS`, HTTP 200, full 65536 bytes, CA verification enabled |

**Observed link outage:** ~122 seconds (22:49:06 to 22:51:08). No manual
reset was required for recovery. `wifi_lost=0` in the rolling sample window
is consistent with no in-flight SSH sample observing link loss; it is **not**
inconsistent with the distinct event counter increasing to 1.

**Post-reconnection transient SSH errors (must not be hidden):**

| Serial time | SSH outcome | Transport | Service | LED |
| --- | --- | ---: | ---: | --- |
| 22:51:53 | `SERVICE_ACCEPT_TIMEOUT` | 6324 ms | 8004 ms | `SSH_FAILURE` |
| 22:52:14 | `SERVICE_ACCEPT_PASS` | 5922 ms | 182 ms | `SSH_READY` |
| 22:53:58 | `SERVICE_ACCEPT_TIMEOUT` | 12006 ms | 8004 ms | `SSH_FAILURE` |
| 22:54:21 | `SERVICE_ACCEPT_PASS` | 11857 ms | 789 ms | `SSH_READY` |
| 22:54:42–22:55:42 | Subsequent SSH PASS | ~3282–3390 ms | ~166–294 ms | `SSH_READY` |

Both timeouts followed `TRANSPORT_PASS` and `HOST_KEY_PASS`: the specific
failure is waiting for SSH SERVICE_ACCEPT, not Wi-Fi association or host-key
trust. Independent HTTPS PASS at 22:51:58 and 22:54:50 supports availability
of that public HTTPS endpoint at those instants. Neither isolates the cause
to the Edge, mobile carrier, server load, route filtering, or transient
post-reconnect conditions. The probe correctly preserves
`filtering_verdict=INCONCLUSIVE`.

**Acceptance:** PASS for detecting Wi-Fi loss, LED indication, reconnect
without a reboot, SNTP reinitialization after renewed IPv4, SSH recovery
and separation of Wi-Fi events from SSH-path sample failures. **Follow-up:**
two real post-reconnection service timeouts and elevated transport times
were observed; do not claim uninterrupted SSH after reconnect.

## 2 — Controlled mobile-data OFF while hotspot Wi-Fi remains associated

**Operator action:** Disable the phone's mobile-data access but leave the
hotspot/Wi-Fi association active (per operator). This excerpt covers SSH
samples **61 and 62**, serial times **23:11:09–23:11:38**, and is not
a complete capture of the outage or recovery.

| Field | `seq=61` | `seq=62` |
| --- | --- | --- |
| SSH result | `DNS_FAIL` | `DNS_FAIL` |
| DNS time | 879 ms | 10 ms |
| RSSI to hotspot | -48 dBm | -46 dBm |
| SSH transport/service | Not tested | Not tested |
| Rolling SSH path failures | 1/12 | 2/12 |
| `wifi_lost` | 0 | 0 |
| `wifi_down_events_since_boot` | 1 | 1 |
| LED | `SSH_FAILURE` | remains `SSH_FAILURE` |

At 23:11:38, the independent DNS diagnostic explicitly reported
`edge_resolve=FAIL` **and** `control_resolve=FAIL` for
`example.com`, with `cause=UNCONFIRMED`. The phone still supplied
a Wi-Fi RSSI and the Wi-Fi-down counter did not increment in this
excerpt. This is evidence of **failed name resolution for multiple
destinations while Wi-Fi association persisted**, consistent with the
operator-induced loss of mobile-data upstream. It does **not** independently
measure the cellular link or prove the entire Internet is unavailable;
DNS settings, captive-network behavior and upstream restrictions can
have similar symptoms.

The contemporaneous `[probe-overall] https=PASS` is a **cached result**
from HTTPS sample **58**, aged **82,124 ms** and **111,242 ms** when
samples 61 and 62 were logged. `https_fresh=1` refers to R1's
360-second freshness budget; **it is not a fresh HTTPS measurement
performed during the outage**. Do not treat it as evidence that public
HTTPS continued to work while mobile data was off.

**Acceptance:** PASS for `DNS_FAIL` classification, stage trace
`stop_stage=DNS`, preservation of Wi-Fi/SSH error separation, independent
DNS control and LED response. **Pending:** no post-restoration DNS,
SSH, or *new* HTTPS sample is present in the provided excerpt. The test
is **not signed off for recovery**. There is no evidence to infer
filtering from either `DNS_FAIL`.

## 3 — Overnight observational window: possible real-world disruption

**Planned:** Leave the ESP32 and Serial Monitor running overnight
2026-10-30 → 2026-10-31, with the phone's **mobile data and hotspot both
ON** and the same known Edge/test settings. This is passive observation,
**not** an induced filtering experiment and not a promise of automatic
classification or notification.

Before the monitoring window, verify these three *new* observations
occur after restoring mobile data:

1. `[quality-link] wifi=UP` and at least two
   `[ssh-deep] END | result=SERVICE_ACCEPT_PASS` entries.
2. `[clock] ready=YES` (an already-correct epoch can survive a short
   Wi-Fi outage; this does not by itself prove a new NTP transaction).
3. A **new** `[https-quality]` sample after restoration with
   `http_code=200`, `bytes=65536/65536`, and `tls_cert_check=ENABLED`.
   An existing `https=PASS` in `[probe-overall]` is insufficient.

If the operator reports an incident, save the original time-stamped
log and annotate **exact local HH:MM:SS and time zone**, MCI/LTE/hotspot
state, and whether an *independent reference device* and the actual NPV
Tunnel client could connect before, during and after the reported event.
Keep at least **10 minutes before** the reported onset and **10 minutes
after** recovery; include all raw `[quality-link]`, `[dns-diag]`,
`[ssh-stage]`, `[ssh-deep]`, `[quality-window]`,
`[https-quality]`, `[clock]`, `[probe-event]` and `[led-state]`
events. Avoid publishing the unredacted logs, credentials or private
endpoints. A separate operator notification about filtering is a
**time anchor/hypothesis**, not a confirmed filtering label.

Comparison questions for the next audit:

- Did Wi-Fi drop (`wifi=DOWN`) or remain UP?
- Did Edge DNS and independent control DNS both fail, only Edge fail,
  or both pass?
- Did a fresh direct HTTPS test succeed/fail/slow, or is only an old
  cached result displayed?
- Did SSH reach transport, pinned host-key verification and
  `SERVICE_ACCEPT`? Exactly which stage failed?
- Did the actual NPV client fail, and did it recover at a similar time?
- Does the degradation persist across consecutive probes, or is it a
  one-off timeout/recovery? `quality-window` evicts old evidence.
- What alternative explanation remains? Separate Wi-Fi, DNS, TLS,
  endpoint/server, transport, control network and **NPV-not-tested**
  hypotheses before any filtering interpretation.

**Critical interpretation gate:** R1 cannot confirm carrier censorship,
NPV authentication, SSH-Direct app throughput or VPN data-path health.
Its `filtering_verdict=INCONCLUSIVE` is correct until stronger independent
comparative evidence is obtained. No automatic failover or alert action
is enabled by this experiment.

## 4 — Morning log after the workstation slept (2026-10-31)

**Observed fragment:** 09:18:31–09:37:02, serial-console local timestamps.
The operator reported that the Windows workstation entered sleep overnight,
preventing continuous Serial capture. **There is no overnight evidence** and no
matched real-world disruption to evaluate from these records.

At 09:19:31 the board reported SSH sequence 9 (`boot_ms=523837`);
after the console printed `History restored` and the monitor was reopened
at 09:25:28, the next recorded SSH sequence was **21**
(`boot_ms=883979`). This proves the on-board uptime/sample counter
advanced during the **visible ~6-minute monitor gap**, not that all missed
SSH cycles passed. Samples **10–20** are absent from the supplied file.
No firmware reset or Wi-Fi-down event appears in the excerpt.

### Recorded SSH and resource observations

- **27/27 visible** `[ssh-deep] END` entries are
  `SERVICE_ACCEPT_PASS`: sequences 7, 8, 9, and 21–44. Do **not** infer
  44/44 observed passes or an all-night pass rate.
- Last rolling window at 09:37:02: `eligible=12 | pass=12 |
  network_failures=0 | wifi_lost=0 | trust_failures=0 |
  wifi_down_events_since_boot=0`.
- Visible SSH transport durations: **3241–3475 ms**; last P90
  **3437 ms**. RSSI between **-67 and -52 dBm** represents the Wi-Fi
  hotspot link, not the cellular modem signal.
- `free_heap` remains in a narrow observed range
  **158208–158776 bytes**; minimum-ever free heap drops from
  **129472 to 101272 bytes** by the end of the captured interval.
  This *historical low-water mark* alone does not prove a memory leak.
- `filtering_verdict=INCONCLUSIVE`, `npv=NOT_TESTED` and
  `auth=NOT_TESTED` are the correct limitations.

### Delayed clock initialization / public HTTPS

- At 09:18–09:26, multiple `[clock] ... ready=NO` reports
  with small unsynchronized epochs persist while SSH succeeds.
- At **09:26:17.790**, `epoch=1793426177 | ready=YES |
  boot_ms=933584`; the clock became usable **15 min 34 s after
  device boot**. This is not necessarily the elapsed time since
  SNTP configuration, because the initial boot/NTP start is not in
  this fragment. Prior runs were substantially faster; the reason
  remains **unresolved**. `udp123=UNVERIFIED` and DNS availability
  alone cannot prove the NTP server transaction path.
- Prior `CLOCK_NOT_READY` HTTPS events are *unmeasured*, with
  zero bytes; they are **not** actual HTTPS failures.
- Four subsequent genuine direct-hotspot HTTPS 64 KiB samples all
  returned **HTTP 200**, **65536/65536 bytes** with certificate
  verification enabled. All four exceeded the firmware's 4000 ms
  body-duration slow threshold:

| Serial time | HTTP body transfer | Approx. body rate | Status |
| --- | ---: | ---: | --- |
| 09:26:38 | 4057 ms | 15 KiB/s | `SLOW_64K_SAMPLE_SUSPECT` |
| 09:29:40 | 5962 ms | 10 KiB/s | `SLOW_64K_SAMPLE_SUSPECT` |
| 09:32:44 | 9750 ms | 6 KiB/s | `SLOW_64K_SAMPLE_SUSPECT` |
| 09:35:40 | 6087 ms | 10 KiB/s | `SLOW_64K_SAMPLE_SUSPECT` |

This repeated slow-body finding is **worth additional comparison** but
cannot be called the customer's Internet throughput, NPV throughput
or filtering. The LED correctly reflects `PUBLIC_HTTPS_SLOW`
after the first measured slow sample.

**Interpretation and next-action gate:** The morning observation supports
a *currently healthy measured SSH path*, with an outstanding clock-start
delay and repeatedly slow public HTTPS samples. It does not validate
overnight uptime or actual filtering. Before the next long monitoring
session on a Windows PC, disable sleep while on AC power (screen-off is
fine) and retain the PlatformIO `-f log2file` output. Verify the log
file is actually progressing and obtain precise incident timestamps
from an independent reference/client when possible.

## Remaining R1 hardware acceptance

- [x] Healthy SSH path, pinned host key, and separate public HTTPS field runs
- [x] SSH-pass LED remains solid while HTTPS clock is not yet ready
- [x] SNTP starts after IPv4, eventually synchronizes on a known healthy run
- [x] Controlled Wi-Fi OFF -> slow LED -> automatic Wi-Fi/SSH recovery
- [x] Controlled mobile data OFF with Wi-Fi retained -> dual DNS failure,
      `DNS_FAIL`, SSH failure LED
- [ ] Mobile-data ON recovery: *new* DNS/SSH/HTTPS observations
- [ ] Deliberate Edge-only failure and independent public control
- [ ] Host-key mismatch: fail closed with a controlled fixture
- [ ] HTTPS-only failure / stalled-response path on real hardware
- [ ] Overnight real-incident matched reference-client audit
- [ ] Extended heap / worker lifecycle and final R1 sign-off

### Source preservation

This is a selective, operator-reviewed extract of observed Serial logs
from 2026-10-30; the raw hardware captures and reference-client evidence
should remain in private operator storage, with times preserved. No live
remote logs, NVLBot telemetry or production service status have been
queried or inferred.
