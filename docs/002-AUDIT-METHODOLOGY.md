# DenaProbe — Comparative Network Audit Protocol (draft)

**Status:** Draft research protocol, not a confirmed filtering fingerprint.

## Primary question

During a real NPV Tunnel SSH-Direct failure on MCI, **where does connectivity first diverge** from known-good observations? Can that divergence be measured reliably from an ESP32 using the phone's Wi-Fi hotspot?

## Observation scenarios

- **A / Working:** Reference client successfully establishes SSH/tunnel and exchanges application traffic.
- **B / Failing:** Reference client cannot establish or use the tunnel; record the exact client error.
- **C / Control:** Independent known-good destinations and, if available, the same server from another network.

Where possible, compare the same server endpoint, SIM, access location, approximate time window, and device settings across A and B.

## Data to record for each run

| Category | Fields |
| --- | --- |
| Context | UTC time, local time zone, scenario label, experiment ID, network operator, access method (phone vs. hotspot), device/OS version |
| Radio and hotspot | Network mode shown on phone (LTE/4G etc.), ESP32 RSSI, Wi-Fi status, local gateway, disconnection events |
| DNS | Resolver used, queried hostname, A/AAAA results (redacted if necessary), lookup duration, error |
| Internet control | Independent control host(s), TCP or HTTPS outcome, latency, error |
| Target TCP | Destination label/port, resolved address, connect duration, success/timeout/reset/error |
| SSH identification | Whether a valid `SSH-2.0` identification string was received, time/error |
| SSH full exchange | Reference-client key exchange, authentication and tunnel-traffic outcomes; not presumed available in ESP32 |
| Evidence | Device logs, anonymized packet-capture observations if available, reference-client screenshot/log, test conditions |

Do **not** upload credentials, tokens, device IMEI, personal data, unredacted IPs of private infrastructure, or raw captures to this public repository.

## Procedure

1. Validate the hardware smoke test separately; do not treat it as a network audit.
2. Validate that the phone is on the intended operator/mobile network, hotspot is 2.4 GHz, and no VPN or proxy changes the ESP32 measurement path.
3. Record the phone's **direct** NPV Tunnel outcome independently; also record the hotspot-connected test outcome. These paths are not automatically equivalent.
4. Run multiple independent baseline controls and DNS/target TCP probes with defined timeouts.
5. Observe target SSH identification and, on a suitable reference machine, the later SSH stages and application data flow.
6. Repeat matched tests while the reference application works and while it fails.
7. Compare timestamps, response classes, latency distributions, and failures. Try to reproduce suspected signatures.
8. Mark each candidate signal as **observed**, **inferred**, or **unverified**; list alternative explanations (server outage, packet loss, DNS, carrier NAT, protocol behavior).
9. Only after the comparison, decide which subset the ESP32 firmware can meaningfully measure.

## Analysis requirements

- Never claim censorship/filtering from TCP failure alone.
- DNS/TCP/SSH banner success does not guarantee working SSH authentication or VPN traffic.
- Different paths (phone itself vs. tethered ESP32) may have different policies.
- Keep negative controls and repeated measurements to reduce false alarms.
- Define detection thresholds *after* collecting evidence, not in advance.

## Exit criteria

Before implementing a classifier, document at least one repeatedly observed difference between healthy and failed outcomes, its counterexamples, how it would be measured on ESP32, and the remaining uncertainty.

## Current action

**Phase 0 complete:** build, USB flash, serial output verified on ESP32-D0WD. A Wi-Fi association/DHCP test succeeded through an Android 2.4 GHz hotspot (carrier route at time of that test not independently confirmed). **Now: Phase 1A healthy MCI baseline**, following [the runbook](003-HEALTHY-BASELINE-RUNBOOK.md). No external DNS/TCP/SSH probes are implemented yet; the actual NPV Tunnel SSH-Direct reference outcome must be measured before declaring a healthy baseline.
