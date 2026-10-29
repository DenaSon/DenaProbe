# DenaProbe

**Evidence-first ESP32 network connectivity research probe.**

DenaProbe is a small hardware research project for comparing healthy and disrupted network connectivity. The first experiment focuses on **MCI (Hamrah-e Aval) mobile internet**, accessed through a **2.4 GHz Wi-Fi hotspot** by an ESP32 DevKit.

> Current status: **v0.0.3 validated on a physical ESP32** (six consecutive DNS/TCP/SSH-ID passes over ~5 minutes). **v0.0.4 implements a status LED and fallback independent TCP control, awaiting local build/flash/hardware verification.** No filtering classifier, VPN client, or production monitor exists.

## Phase boundaries

- **Phase 0 (passed):** Verify USB flashing and serial output on the ESP32.
- **Phase 1 / Step 0 (current):** Validate ESP32 Wi-Fi association with an MCI LTE phone hotspot.
- **Phase 1A:** Audit real healthy vs. failed connections using independent controls and a reference client.
- **Phase 1B:** v0.0.3 hardware validated for DNS, TCP, and unauthenticated SSH identification. v0.0.4 adds LED indication and an independent public TCP control on Edge probe failures; validation pending.
- **Later:** Evaluate SIM800L 2G/GPRS independently. It is **not** part of Phase 1.

A successful DNS lookup, TCP connection, or SSH identification exchange **does not prove** that SSH authentication or a VPN tunnel works. A failed connection **does not by itself prove filtering**.

## Development environment

- Windows 10, Visual Studio Code, PlatformIO IDE
- ESP32 DevKit (PlatformIO board ID: `esp32dev`)
- C++ using Arduino framework

## Wi-Fi link test (v0.0.2)

1. In `include/wifi_config.h`, change `WIFI_SSID` to your phone hotspot's exact network name.
2. Make sure the phone hotspot is running on 2.4 GHz and mobile data is on MCI LTE.
3. Connect the ESP32 with a data-capable Micro-USB cable.
4. Run `pio run` to build.
5. Run `pio run -t upload` to flash the board.
6. Run `pio device monitor -b 115200` to inspect the serial log.

Expected: `[wifi] CONNECTED`, assigned IP/gateway/DNS, periodic `[wifi] OK` with RSSI. If the SSID is still the placeholder, the firmware prints `[config] ERROR` and does not attempt Wi-Fi.

**Scope:** Only association, DHCP information, and signal diagnostics. No external requests, VPN, DNS checks, or filtering detection.

## Documentation

- [Project scope](docs/001-PROJECT-SCOPE.md)
- [Comparative audit methodology](docs/002-AUDIT-METHODOLOGY.md)
- [Healthy MCI baseline runbook](docs/003-HEALTHY-BASELINE-RUNBOOK.md)
- [SSH feasibility and hardware field observations](docs/007-SSH-FEASIBILITY-SPIKE.md)
- **[DPT/1 cross-platform telemetry contract](docs/008-DPT-TELEMETRY-CONTRACT-V1.md)** ([codes](contracts/dpt/v1/code-registry.json) · [JSON Schema](contracts/dpt/v1/telemetry.schema.json) · [fixtures](contracts/dpt/v1/fixtures.json)) — documentation only; firmware/NVLBot integration pending.

## Public repository safety

**Important:** At the owner's explicit request, the **disposable test hotspot passphrase** in `include/wifi_config.h` was committed to this **public repository**. Git history retains previously committed credentials. Anyone who learns the SSID and is within radio range could attempt to connect; change the passphrase when no longer testing and never reuse it for other networks or accounts. This is a **one-off experiment exception**, not a recommended credential-handling pattern.

Never commit **other** Wi-Fi passwords, SSH credentials, device identifiers (IMEI, etc.), customer information, raw packet captures containing sensitive data, or tokens. Publish only reviewed/redacted experiment summaries.

## License

No license has been selected yet. A public repository is not automatically an open-source software license.

## Phase 1B: Minimal Edge probes (v0.0.3 validated on hardware)

This firmware preserves the Wi-Fi status checks and adds a **once-per-60-second** diagnostic sequence on the *public Edge* configured in the NPV Tunnel profile: DNS A lookup, TCP connect to the Edge SSH port, and passive SSH `SSH-2.0-` identification-line read (4-second timeout). It does **not** log in, send an SSH password, run KEX, test the Core egress, authenticate NPV, or diagnose censorship.

**Do not configure the hidden Core address.** The public NPV domain is only used locally in an ignored file.

From PowerShell **in the cloned repository directory**:

```powershell
Copy-Item include\probe_private.h.example include\probe_private.h
notepad include\probe_private.h
pio run
pio run -t upload
pio device monitor -b 115200
```

Edit `PROBE_EDGE_HOST` to the publicly accessible hostname configured in the client. Keep `PROBE_EDGE_PORT` equal to the real SSH entry port (currently 2252 for this test). The `include/probe_private.h` file is listed in `.gitignore` to protect infrastructure details. Do not commit raw serial logs or credentials.

Expected tags: `[dns] PASS|FAIL`, `[tcp] PASS|FAIL`, `[ssh-id] PASS|FAIL`, `[probe] END | stage=... | no_filtering_verdict`. Wi-Fi reconnect, negative controls, and uncertainty matter; a PASS **never** means VPN app traffic is known working, and a FAIL **never** proves intentional filtering. The SSH identification line is **not authenticated** and cannot substitute for the reference NPV Tunnel application outcome.

**Verification status:** The owner built and flashed v0.0.3 and provided six successful serial probe cycles from physical hardware. See `docs/004-AUDIT-OBSERVATIONS.md`. This positive baseline does not test failure recognition.

## v0.0.4 — Edge rotation awareness, independent control, status LED (unverified)

**DNS, not IP pinning:** The private setting `PROBE_EDGE_HOST` holds the public **Edge hostname**, not the IP address or hidden Core. On every ~60-second test, `WiFi.hostByName()` requests its current IPv4 mapping and the probe connects to that result. When DNS returns a different IP than on the last successful cycle, serial prints `[dns] EDGE_IP_CHANGED`. **DNS caching and TTL propagation can delay a rotation**; this does not bypass caching or resolve all A records.

**LED (default: GPIO2, active-HIGH):** Many ESP32 DevKit boards expose an onboard blue LED on GPIO2, but not all. If your board lacks a controllable LED on GPIO2 or uses inverted polarity, set `PROBE_LED_PIN` and `PROBE_LED_ACTIVE_LOW` in **local ignored** `include/probe_private.h`. Do not overwrite this file with the template if already configured. LED updates are best-effort while network operations can block for several seconds.

| LED state | Pattern | Meaning |
|---|---|---|
| `WIFI_WAIT` | 1 second ON, 1 second OFF | Wi-Fi not yet connected, or disconnected |
| `HEALTHY` | solid ON | Last DNS, TCP/2252, and SSH identification probe passed; **NOT** NPV health |
| `SUSPECT` | double short flash, 2-second repetition | First/second Edge probe failure; or repeated failure without working public control |
| `EDGE_ISSUE` | fast blink (125 ms ON, 125 ms OFF) | **3+ consecutive Edge probe failures AND an independent public TCP control passed**; suspected Edge-specific fault, NOT proven filtering |

**Independent control:** On each failure of Edge DNS/TCP/SSH-ID, v0.0.4 resolves `example.com` and attempts a TCP socket to public port 443 with a 3-second TCP timeout. Passing this proves only this distinct public TCP connection, **not HTTPS/TLS or whole-internet health**. A failed control leaves the alert in `SUSPECT`, without concluding that mobile Internet is completely down. This fallback control itself may be subject to access restrictions or server faults. The board runs no SSH authentication, does not use the Core address and does not measure NPV application traffic.

**Local upgrade (PowerShell in your existing clone):**
```powershell
Set-Location "D:\denaProbe\DenaProbe"
git pull --ff-only
pio run
pio run -t upload
pio device monitor -b 115200
```

Leave `include/probe_private.h` in place. Firmware defaults to GPIO2 when optional LED definitions are absent. Expected new lines: `[led] mode=...`, `[diagnostic] ... | no_filtering_verdict`, and on failed Edge probes `[control] PASS|FAIL | type=PUBLIC_TCP_443 ...`.

**Verification:** v0.0.4 was committed but **has not yet been built, flashed or visually verified on the user's board**. Do not describe LED patterns or independent-control classification as tested until the owner reports hardware evidence. Never turn a single probe failure into a filtering conclusion.



**Hardware scope decision (2026-10-28):** Keep only the onboard blue GPIO2 LED for all DenaProbe status indications. Do **not** add an RGB LED or other LED hardware. The owner has visually verified steady ON on a healthy probe and blinking after inducing a connection disturbance. No fault-time serial trace was captured, so the exact blinking state (Wi-Fi waiting vs suspect vs confirmed-by-control repeated Edge issue) has **not** been distinguished on hardware. Record a new observation rather than declaring filtering from blink alone.
