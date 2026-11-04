# DenaProbe A1 — Firmware SSH Password Authentication review
**Date:** 2026-11-04
**Parent:** [017 — Password SSH / NPV path](017-DEEP-SSH-PASSWORD-DATA-PATH-FIELD-PLAN-2026-11-04.md)
**Status:** Implementation complete pending CI/review; **A2 physical pilot NOT approved.**

## A1 source and security boundary

- Deep mode 0 preserves R3 public-key experiment, mode 1 enables password authentication. The new PlatformIO password environment is independent of the default, feasibility and key-based builds. Normal firmware still has Deep OFF.
- User (1–48 chars) and secret (1–128 chars) required in password mode. Real credentials belong ONLY in local ignored include/probe_private.h; examples/CI use empty or synthetic values, not customer secrets.
- SSH_OPTIONS_USER set before ssh_connect. SHA256 server host-key pin verified after KEX and BEFORE ssh-userauth service or a password API call; host mismatch aborts. Client login password is NOT host-key pin.
- ssh_userauth_password retries SSH_AUTH_AGAIN only within a fixed 8-second wall-clock deadline. Rejected and partial authentication never retries/falls back. Wi-Fi loss stays local/UNKNOWN. Existing codes: 1 success, 10 rejection, 11 timeout, 12 error, 90 local; no filtering incident.
- The existing allowlisted loopback direct-tcpip two-transfer and dwell code is reused; no shell, PTY, or arbitrary forwarding added. Destination permission and actual responder are NOT validated by A1.
- DeepEvidence.authCode is local Serial metadata only, not a DPT/2 wire field. Serial reports auth outcome/time, channel states and bytes, dwell, session elapsed and heap/stack. No identity, password, key, auth error text or response body is printed.
- DPT/2 signed codec, numeric registry, Collector, database, NPV routes and server accounts unchanged.

## Test and review matrix

| Gate | Required evidence |
|---|---|
| Default firmware | Clean esp32dev build, Deep off |
| Feasibility | Clean esp32dev_ssh_feasibility build |
| Legacy key experiment | Clean esp32dev_r3_deep_compile build |
| New password build | Clean esp32dev_a1_password_compile build |
| Host negative | Wrong/partial credential, auth timeout/error, bad host pin, Wi-Fi loss, channel denied/timeout |
| Host positive | AUTH_AGAIN then success and two full samples |
| Payload and contracts | First-pass second-timeout, bad body, reset during dwell, synthetic password never serialized, existing R1/DPT tests |
| Production | No flash, Core, Telegram, SSHD or DB changes |

Host tests simulate libssh. A successful compiler run does not establish runtime authentication on the actual board or NPV target.

## Gate to A2 (HOLD)

Before any board flash, save the actual board firmware/partition layout and known-good rollback image; independently verify the SSH host key pin; confirm effective server password versus keyboard-interactive policy and an authorized forwarding target. A2 needs explicit pilot approval, serial memory/watchdog measurements, at least 30 stable cycles and MCI/RighTel same-target reference comparisons. No Core rollout before accepted A2.

A1 deliberately excludes OTA, credential-management API, arbitrary forwarding, live SSHD changes and universal NPV equivalence claims.
