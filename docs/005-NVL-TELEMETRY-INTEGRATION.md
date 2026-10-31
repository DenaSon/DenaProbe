# DenaProbe v0.0.5 — Optional NVL Python bot telemetry

**Source status:** Implemented in feature branch for review; **not built/flashed**
on hardware. Existing ESP32 v0.0.4 blue-LED diagnostic works unchanged with no
telemetry configuration.

## Why a hostname and independent HTTPS path?

- **Edge target:** Keep existing ignored \`include/probe_private.h\` with
  \`PROBE_EDGE_HOST\` set to the NPV Tunnel public **hostname**, not its
  transient IP. Each ~60s cycle resolves a fresh answer and probes that Edge.
- **Report collector:** Separate HTTPS hostname, **not the Edge**, and not a
  public DNS record revealing the hidden Core IP. This address is configured
  only once after a separately controlled NVL Python receiver is set up.
- **Secrets:** Only the ignored \`include/probe_report_private.h\` contains the
  device token and the public root CA PEM used to validate the collector. The
  token is not the Telegram bot token or any SSH password.

## Enable after the Python API is securely deployed

Run from the Windows 10 PowerShell project directory:

\`\`\`powershell
Set-Location "D:\denaProbe\DenaProbe"
Copy-Item .\include\probe_report_private.h.example .\include\probe_report_private.h
notepad .\include\probe_report_private.h
pio run
pio run -t upload
pio device monitor -b 115200
\`\`\`

Configure the **separate telemetry ingress** host, device ID matching the NVL
receiver configuration, path \`/v1/reports\`, freshly random per-device bearer
token, declared carrier (e.g. MCI), and trusted PEM root that validates the
ingress TLS certificate chain. Replace all placeholders. Do not commit the
local file. ESP32 obtains network time using SNTP before making the strict
certificate-validated HTTPS request. **It never calls \`setInsecure()\`.**

If the private report config file does not exist at build time, telemetry
is compiled out and the firmware continues exactly the previous probes/LED
behavior; no secret or endpoint is baked into the public repository.

After successful probe cycles, expected lines include:
\`\`\`text
[dns] PASS ...
[tcp] PASS ...
[ssh-id] PASS ...
[diagnostic] edge=SSH_ID_PASS | led=HEALTHY | no_filtering_verdict
[telemetry] SENT | pending=0
\`\`\`

\`[telemetry] DEFERRED\` means HTTPS/time/server unavailable and the record
stays in the in-RAM queue. At most 8 reports are retained and at most 2
transmitted per probe cycle. Power loss loses pending RAM entries. The next
cycle is normally one minute later. The server records **its receive time**
for freshness, not the untrusted ESP32 clock.

## Important limitations

- TLS root certificate and SNTP must work **on the ESP32's actual mobile
  underlay**; this is **not verified** until a physical device POST succeeds.
- A successful remote report does not validate an NPV authenticated tunnel;
  the board still tests DNS/TCP/SSH identification only.
- Failure to upload cannot be interpreted as Edge filtering: telemetry
  ingress, DNS, CA, time sync, mobile connectivity and collector service
  can all independently fail.
- An external HTTPS endpoint that reveals the hidden Core address or
  depends on the rotating Edge must not be activated. Use an independent
  public ingress with an authorized private upstream path.

## Cross-project contract

See \`DenaSon/nvl-bot/docs/DENAPROBE_TELEMETRY_V1_2026-10-28.md\` for
the versioned JSON contract, per-device auth, independent SQLite data model,
Telegram admin view and controlled deployment gates. Do **not** run any live
NVL failover, Core network, Cloudflare or DNS mutation to enable this.
