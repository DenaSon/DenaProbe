# DenaProbe — Project Scope (v0)

## Purpose

Build a small, reproducible hardware probe to **detect and characterize connectivity failures earlier**, based on measured evidence rather than a binary “filtered/not filtered” guess.

## Immediate scope

- One ESP32 DevKit, using **built-in 2.4 GHz Wi-Fi only**.
- One reference access network: **MCI (Hamrah-e Aval) LTE via phone hotspot**.
- One reference application scenario: **NPV Tunnel SSH-Direct** (actual user experience is the ground truth).
- Compare healthy and failed observations **before** implementing detection logic.
- Start with local USB/serial output, no cloud backend.

## Out of scope for the first phase

- SIM800L (2G/GPRS), 4G modem hardware, multi-operator testing.
- Dashboards, Laravel integration, automated Telegram alerts, over-the-air updates.
- Claiming a filtering cause from a single failed DNS/TCP/SSH probe.
- Implementing a VPN client or using customer credentials in firmware.

## Non-negotiable research constraints

1. Label the **tested network path** explicitly. ESP32-through-hotspot is not identical to on-device phone traffic.
2. Use a reference NPV Tunnel client and log its observed success/failure independently.
3. Record independent control destinations to separate general internet failure from target-specific problems.
4. Separate DNS, TCP, SSH identification, key exchange, authentication, and actual tunnel traffic; never infer later stages from earlier ones.
5. Keep timestamps, timeouts, repetitions, source/destination metadata and uncertainty in evidence logs.
6. Treat a network error as a **measurement**, not proof of why it occurred.
7. Keep sensitive details out of the public repository.

## Phase gates

- **0 / Smoke test complete:** The correct board can be built, flashed, and read over USB serial.
- **1A / Audit complete:** Repeated matched observations of working and failing connections, including controls and real reference-client outcomes.
- **1B / Probe feasibility confirmed:** ESP32 can measure one or more meaningful differences repeatably.
- **First release:** Only after false positives/negatives are evaluated with real examples.

No unapproved scope expansion.
