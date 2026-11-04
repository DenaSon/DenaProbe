# DenaProbe Lite HTTP-over-SSH: board deployment (2026-11-04)
Status: source release, requires Core route3 live and SSHD per-user permit.

## Goal and measured path
ESP32 → MCI hotspot → \`n1.nvlsup.com:2252\` (DNS-resolved Edge IP
recorded in signed \`ei\`) → pinned ED25519 SSH handshake →
password login → two separate SSH \`direct-tcpip\` channels in that
**one** SSH session to \`speedtest.tele2.net:80\`.

On each channel the board sends plain HTTP/1.1:
\`GET /1MB.zip\`, \`Range: bytes=0-8191\`, \`Connection: close\`.
It accepts only HTTP 200/206 and counts 8,192 bytes of HTTP **BODY**;
headers and unsuccessful redirects/statuses do not count. Five seconds
separate the two readings. The official Tele2 HTTP test-file service is
public; no second VPS, new domain or dedicated responder is required.

This checks the selected HTTP path through SSH. It does NOT simulate a
complete NPV client SOCKS/Tunnel session, establish all customer
destinations, or attribute failure to ISP filtering. The third-party
service may fail independently, and HTTP over port 80 is not
end-to-end TLS-protected outside the SSH terminator.

## Strict operator prerequisites
1. Core running master containing DPT/2 signed \`rt=3\` validation and
   Rich notification classifier (nvl-bot PR #282), not merely GitHub-merged.
2. Static test site reachable **from the SSH terminator**:
   \`curl -4 -I --max-time 10 http://speedtest.tele2.net/1MB.zip\`
   (the actual signed board test uses HTTP GET and a Range).
3. Authorized test account has SSH \`direct-tcpip\` to exactly
   \`speedtest.tele2.net:80\` (OpenSSH: \`AllowTcpForwarding local\`,
   \`PermitOpen speedtest.tele2.net:80\`), without broadening the global
   SSHD policy. Inspect current restrictions before modifying any
   \`Match User\` block; validate \`sshd -t\` before a safe reload.
4. Keep the existing known pinned SSH host key. No secrets in GitHub.

## Local Windows 10 / PlatformIO configuration
Use local ignored \`include/probe_private.h\` with existing verified
\`PROBE_EDGE_HOST\`, \`PROBE_EDGE_PORT\`, \`PROBE_SSH_PIN_SHA256_HEX\`,
\`PROBE_DEEP_USER\`, \`PROBE_DEEP_PASSWORD\`, and:
\`\`\`cpp
#define PROBE_DEEP_ENABLED 1
#define PROBE_DEEP_AUTH_MODE 1
#define PROBE_DEEP_AUTH_ONLY 0
#define PROBE_DEEP_REMOTE_HOST "speedtest.tele2.net"
#define PROBE_DEEP_REMOTE_PORT 80
#define PROBE_DEEP_EVERY_N_CYCLES 2
\`\`\`
The latter legacy count is only an auth-settings valid range guard in
Lite; HTTP Lite run frequency is \`PROBE_LITE_EVERY_N_CYCLES=1\` in
the build flags. Do not set a 127.0.0.1 destination. \`PROBE_LITE_SAMPLE_BYTES\`
is fixed at 8192, \`PROBE_LITE_DWELL_MS=5000\`.
In local ignored \`include/telemetry_private.h\`, retain/provision
\`PROBE_DPT_ENABLED 1\`, correct \`/api/dpt/v2/telemetry\` URL,
\`v2-\` key ID, 64-hex HMAC secret, trusted verified CA, target ID and
\`PROBE_DPT_OFFLINE_SMOKE_TEST 0\`; do not reuse DPT/1 credentials.

From PowerShell (change path and COM port as appropriate):
\`\`\`powershell
cd "D:\denaProbe\DenaProbe"
git switch master
git pull --ff-only
pio run -e esp32dev_lite_wire_compile -t clean
pio run -e esp32dev_lite_wire_compile
pio run -e esp32dev_lite_wire_compile -t upload --upload-port COM6
pio device monitor --port COM6 --baud 115200
\`\`\`
If PlatformIO build fails or the public destination is unavailable,
do not flash/enable data-plane alerts. Avoid serial console passwords;
copy only status/error lines when sharing logs.

## Acceptance
- SSH pinned host key PASS; one password \`AUTH_SUCCESS\`
- \`[deep] TRANSFER_1\` and \`TRANSFER_2\` code 1, 8192/8192
- \`[deep] DWELL\` approx 5 seconds
- HTTPS signed DPT/2 telemetry ACK=200; \`z.rt=3\`,
  \`j\`, \`ei\` visible in original raw_json record
- Rich admin shows current Edge DNS IP/domain and
  public HTTP witness; superadmin alerts only for repeated classified
  incidents, never claim censorship on isolated endpoint failures
- Rollback: previous board Lite source and previous Core release in
  compatible order. Historic rt=1/2 source remains backward-compatible.

Keep the historical 127.0.0.1:18180 0x5A Core-only service unchanged;
route3 does not use it.
