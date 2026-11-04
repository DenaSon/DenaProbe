# DenaProbe B3 — MCI Edge SSH Login Monitoring | Board Stage 1

Date: 2026-11-04
Status: firmware candidate; **not flashed or field accepted**.

## Purpose and boundaries
ESP32 over MCI mobile hotspot -> public Edge DNS/TCP port 2252 -> current SSH
terminator behind Edge -> verify pinned ED25519 host public key -> password
authentication for the already-provisioned restricted test identity.
No forwarding channel, Core-loopback responder, public Internet egress or NPV
customer VPN health claim. Core and Edge are abroad; the measurement vantage
point is the board on MCI in Iran. HTTPS Collector upload is a separate path.

Preauth success is not password login success. The B3 code records the auth
result independently in AuthEvidence, retaining DNS/TCP/KEX/SERVICE_ACCEPT
and signed telemetry. Auth status codes: 1 success; 10 rejected/partial;
11 timeout; 12 libssh/protocol error; 90 local/unmeasurable. Host-key mismatch
must fail closed BEFORE sending credentials. No password/user in logs.

## Phase 1: safe board-only mode
PlatformIO: esp32dev_b3_edge_auth_compile.
Operator changes only ignored local include/probe_private.h to
PROBE_DEEP_AUTH_ONLY=1 (keep known-good Edge host, port, account/password,
fingerprint, DPT/2 identity/CA unchanged). The compile gate rejects other
auth modes and accidental B1/B2 forwarding pilots. Serial emits edge-auth
outcome and elapsed time. No ssh_channel_new/open_forward and no 20s dwell.

PROBE_B3_AUTH_WIRE=0 intentionally preserves the current Core DPT/2
contract: TCP/SSH/HTTPS remain signed and ACKed, while B3 auth is local
Serial evidence ONLY. The existing detector D0 behavior stays in place;
Telegram does not yet display or alert on authentication until Phase 2.
No new Core deployment, DB migration or responder change is needed here.
Auth runs every PROBE_DEEP_EVERY_N_CYCLES successful preauth cycles.
Nominal SSH start interval is 30s but heavy worker scheduling can delay it.

## Phase 2 handoff (DO NOT flash the future wire profile yet)
PlatformIO candidate: esp32dev_b3_edge_auth_wire_compile.
New signed optional DPT/2 object:
  "j":{"u":auth_completion_uptime_ms,"s":auth_code,"ms":auth_elapsed_ms}
No password, username, host/IP or payload. There is no "z" Loopback/Deep
object in B3. The current Core validator does NOT accept the new "j" field:
updating the B3 firmware to this profile before Core Phase 2 is deployed
would break telemetry acceptance. Phase 2 will add server validation, DB
persistence, classifier, Rich UI and deduped incident/recovery notifications.
Wrong password, host-key problems, missing Wi-Fi or missing telemetry must
NOT be mislabeled as confirmed filtering; separate outage and device-silent
signals from authentication/configuration failures.

## Checks before field acceptance
- Host C++ cases in tests/test_b3_edge_auth.cpp: success, denied, timeout,
  error, host-key mismatch, hotspot loss; zero forwarding; both wire variants;
  no credential exposure or older Deep regressions.
- CI compiles default, A2, B1, B2, B3 safe and reserved wire environment.
- Flash only the stage 1 B3 profile; verify Serial has edge-auth AUTH_SUCCESS
  without TRANSFER_1, DWELL or TRANSFER_2.
- Verify Core DPT/2 HTTP200 ACK and signed records without "j" and "z".
- Preserve TLS certificate validation and keep old firmware rollback image.
- B3 Stage 1 is accepted only after actual ESP32 serial and Core ACK evidence.

No source/CI completion proves field deployment. Phase 2 stays gated.
