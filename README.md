# DenaProbe

**Evidence-first ESP32 network connectivity research probe.**

DenaProbe is a small hardware research project for comparing healthy and disrupted network connectivity. The first experiment focuses on **MCI (Hamrah-e Aval) mobile internet**, accessed through a **2.4 GHz Wi-Fi hotspot** by an ESP32 DevKit.

> Current status: hardware smoke test passed on ESP32-D0WD; **Wi-Fi link validated on Android hotspot; MCI healthy audit commencing**. No filtering classifier or production monitoring firmware exists yet.

## Phase boundaries

- **Phase 0 (passed):** Verify USB flashing and serial output on the ESP32.
- **Phase 1 / Step 0 (current):** Validate ESP32 Wi-Fi association with an MCI LTE phone hotspot.
- **Phase 1A:** Audit real healthy vs. failed connections using independent controls and a reference client.
- **Phase 1B:** Implement only the measurements supported by the observed evidence, via ESP32 built-in Wi-Fi.
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

## Public repository safety

**Important:** At the owner's explicit request, the **disposable test hotspot passphrase** in `include/wifi_config.h` was committed to this **public repository**. Git history retains previously committed credentials. Anyone who learns the SSID and is within radio range could attempt to connect; change the passphrase when no longer testing and never reuse it for other networks or accounts. This is a **one-off experiment exception**, not a recommended credential-handling pattern.

Never commit **other** Wi-Fi passwords, SSH credentials, device identifiers (IMEI, etc.), customer information, raw packet captures containing sensitive data, or tokens. Publish only reviewed/redacted experiment summaries.

## License

No license has been selected yet. A public repository is not automatically an open-source software license.
