# DenaProbe

**Evidence-first ESP32 network connectivity research probe.**

DenaProbe is a small, open-source hardware research project for comparing healthy and disrupted network connectivity. The first experiment focuses on **MCI (Hamrah-e Aval) mobile internet**, accessed through a **2.4 GHz Wi-Fi hotspot** by an ESP32 DevKit.

> Project status: **hardware smoke test / pre-audit**. There is no filtering classifier or production monitoring firmware yet.

## Phase boundaries

- **Phase 0:** Verify USB flashing and serial output on the ESP32.
- **Phase 1A:** Audit real healthy vs. failed connections using independent controls and a reference client.
- **Phase 1B:** Implement only the measurements supported by the observed evidence, via ESP32 built-in Wi-Fi.
- **Later:** Evaluate SIM800L 2G/GPRS independently. It is **not** part of Phase 1.

A successful DNS lookup, TCP connection, or SSH identification exchange **does not prove** that SSH authentication or a VPN tunnel works. A failed connection **does not by itself prove filtering**.

## Development environment

- Windows 10, Visual Studio Code, PlatformIO IDE
- ESP32 DevKit (PlatformIO board ID: `esp32dev`)
- C++ with Arduino framework for the initial hardware check

## Hardware smoke test

1. Connect the ESP32 to a computer with a **data-capable USB cable**.
2. Open this repository in VS Code with PlatformIO IDE installed.
3. Run `pio run` to build.
4. Run `pio run -t upload` to flash the board.
5. Run `pio device monitor -b 115200` to view the serial log.

Expected: a one-time device-information banner, followed by a periodic `OK` message. The smoke-test firmware does not connect to Wi-Fi or transmit data.

## Documentation

- [Project scope](docs/001-PROJECT-SCOPE.md)
- [Comparative audit methodology](docs/002-AUDIT-METHODOLOGY.md)

## Public repository safety

**Never commit** Wi-Fi credentials, SSH usernames/passwords, private IPs, device identifiers (IMEI, etc.), raw packet captures containing sensitive data, tokens, or customer information. Publish only reviewed/redacted experiment summaries.

## License

No license has been selected yet. A public repository is not automatically an open-source software license.
