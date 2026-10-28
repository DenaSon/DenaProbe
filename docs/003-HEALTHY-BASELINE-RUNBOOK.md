# DenaProbe — Healthy MCI Baseline Runbook (Phase 1A)

**Status:** Prepared protocol. **No verified healthy SSH-Direct observations have been recorded yet.**

## Goal

Capture repeated **actual successful NPV Tunnel SSH-Direct sessions** and independent connectivity controls over a known MCI (Hamrah-e Aval) LTE/4G access path. This is an evidence-collection procedure, **not** a filtering fingerprint, classifier, or production firmware specification.

## Proposed topology

```text
MCI SIM (LTE/4G mobile data)
        |
 Android phone (mobile data on, VPN/proxy off)
        |
  2.4 GHz Wi-Fi hotspot (SSID: dena288)
        |                         |
 ESP32 Wi-Fi station         iPhone reference client
 (serial diagnostics)        (Wi-Fi to Android, NPV Tunnel)
```

The reference iPhone's mobile-data path should be disabled during the test so its NPV traffic is actually using Android hotspot Wi-Fi. Verify the Wi-Fi connection and avoid changing proxy/VPN settings on the hotspot provider.

The ESP32 and iPhone share an upstream but are **not packet-identical paths**. Hotspot NAT/tethering rules and per-device DNS handling can differ. A phone running NPV directly on cellular is a *separate* comparison case; never combine results without a path label.

## Preconditions (record, do not assume)

- [ ] Android mobile data is from the **MCI SIM** on LTE/4G (not Wi-Fi and not another SIM).
- [ ] Android VPN/proxy is disabled; 2.4 GHz hotspot is on.
- [ ] iPhone joined the Android hotspot; iPhone cellular data is disabled for this run.
- [ ] ESP32 `[wifi] CONNECTED` reported for the same hotspot **during this MCI run**.
- [ ] Local time and timezone are recorded; ideally also UTC.
- [ ] NPV Tunnel profile type is confirmed as **SSH-Direct**, not another mode.
- [ ] No test account secrets, authentication data, or unredacted customer identifiers are included in any public record.

## Each baseline round (minimum 3 sequential rounds)

1. **Reference without VPN:** Make sure NPV tunnel is disconnected; load two *independent* previously reachable ordinary HTTPS control destinations. Record the URL/host label, outcome, approximate elapsed time, and errors. Avoid assuming any particular public site is reachable on MCI.
2. **Reference VPN connect:** Connect NPV Tunnel using the same selected SSH-Direct profile each round. Record attempt start time, whether the app says connected, time to connected, and the exact UI/log error if unsuccessful.
3. **Actual tunnel traffic:** After the NPV app reports connected, load an HTTPS page through the tunnel and record whether it *actually transfers data*. A “connected” UI alone is not a valid working result. Record any tunnel byte counters or relevant redacted app log evidence when available.
4. **ESP32 record:** In a nearby time window, capture serial lines showing Wi-Fi association status, DHCP IP/gateway/DNS, RSSI, disconnects, and uptime. ESP32 firmware v0.0.2 is **link-only** and cannot yet prove general internet access, DNS success, TCP success, SSH exchange, or VPN functionality.
5. **Repeat:** Disconnect NPV and repeat with the same MCI SIM, location, hotspot settings, test profile, and similar timing. Record any changes, rather than silently dropping failed rounds.

## Sanitized observation sheet

Only create reviewed, redacted **summaries** in the public repository. Raw screenshots and logs that contain credentials or private target details should remain local.

| Field | Round A1 | Round A2 | Round A3 |
| --- | --- | --- | --- |
| Local timestamp + timezone | TBD | TBD | TBD |
| Scenario label | Intended healthy | Intended healthy | Intended healthy |
| Android cellular operator + radio mode | Not yet verified | | |
| Test path | iPhone -> Android hotspot -> MCI | same | same |
| ESP32 connected + RSSI (dBm) | Not yet measured on MCI | | |
| HTTPS control #1 without VPN | Not tested | | |
| HTTPS control #2 without VPN | Not tested | | |
| NPV profile type confirmed SSH-Direct | Not confirmed | | |
| NPV connect outcome | Not tested | | |
| Time to NPV connect (s) | Not measured | | |
| Tunnel HTTPS application data transferred | Not tested | | |
| NPV error / warning (if any) | None recorded | | |
| Confidence / deviations | Pending | | |

## Target-endpoint measurement plan (later in audit)

After a reference run confirms the actual SSH-Direct target hostname and port **without disclosing credentials**, prepare an isolated, configurable ESP32 diagnostic probe to log:

- DNS name lookup timing and outcome.
- TCP connect duration/error to the user-approved target endpoint.
- If technically applicable and without attempting authentication, whether an SSH identification string arrives and when.
- Separate independent TCP/HTTPS controls and explicit timeout/retry behavior.

**Do not assume** a valid SSH banner means key exchange, authentication, UDPGW, or application tunnel works. Some SSH servers may wait for the client banner. Do not equate a TCP timeout or reset with confirmed filtering.

This is instrumentation for comparison, **not** implementation of the detection algorithm. No SIM800L use in Phase 1.

## Transition / exit checks

A round counts as a **healthy reference** only when the actual NPV SSH-Direct session works and application data transfers. An ESP32 Wi-Fi connection alone is insufficient.

Do not finalize a detection design until repeatedly matched **healthy and failed** scenarios and negative controls are collected, analyzed, and alternative causes evaluated.
