# DenaProbe — Filtered-Path / Degraded-Network Audit Evidence

**Documented:** 2026-10-29  
**Source windows:** SSH incident on 2026-10-22 (operator-supplied retrospective audit); Windows HTTPS comparisons on 2026-10-28/29 (operator-supplied command output).  
**Status:** Evidence synthesis and **design input only** — NOT an ESP32 filtered-path hardware validation, censorship attribution proof, or approved firmware implementation.  
**Canonical research process:** [comparative methodology](002-AUDIT-METHODOLOGY.md) · [earlier DenaProbe observations](004-AUDIT-OBSERVATIONS.md).

## 1. Executive finding

Two distinct failures demonstrate a shared diagnostic blind spot:

1. **NVLBot SSH-Direct, MCI:** The operator classifies the former Edge public IP as **filtered for affected MCI users**: customer connections were prevented even though TCP and the SSH identification/KEX stages worked. The same endpoint progressed further from Rightel. Reported paired packet captures showed client-side ACK and follow-up data that were **not observed** at the Edge capture vantage.
2. **YouTube HTTPS, Windows on reported MCI path:** For each of **two public Google frontend IPs**, `www.google.com` completed TLS 1.2 and returned HTTP 200, whereas `www.youtube.com` failed during Schannel TLS processing on that same IP. Ordinary local resolution of YouTube previously returned an RFC1918 address.

These are **two separate protocol/path experiments**. The YouTube result is not a reproduction of the SSH failure; neither alone identifies the exact filtering device, filtering rule, DPI mechanism or packet-drop location.

**Design rule:** `DNS_PASS` or `TCP_PASS` or `SSH_BANNER_PASS` must **never** be presented as proven SSH authentication readiness, NPV Tunnel usability, or proof of no filtering.

## 2. Evidence provenance and confidentiality

- **Operator report (2026-10-22):** A retrospective incident narrative with tabulated SSH progress and paired packet-capture findings. The underlying `.pcap`/`.pcapng` files were **not provided for independent inspection** in this documentation pass. Packet-level statements below are accurately attributed to that report, not independently verified packet analysis.
- **Direct console excerpts supplied in conversation (2026-10-28/29):** Verbose Windows `curl.exe` logs for YouTube and Google, including explicit `--resolve` pinning and TLS 1.2 controls. This is command-output evidence; simultaneous operator-ASN/OS route, capture and app result are not present in those specific logs.
- **Operator classification:** “Filtered Edge IP” describes the real customer-facing impact and the operator's cross-network diagnosis. **Cause/mechanism** remains a separate, unproven claim.
- **Publication policy:** This public document omits original Edge and Core IPs, WG addresses, client public/private addresses, identifying domains, credentials, raw packets, raw logs, hotspot identifiers and tokens. Generic Edge/Core and public **third-party** Google frontend addresses alone are used.

## 3. SSH incident: affected MCI path versus working Rightel path

**Reported topology, intentionally anonymized:**

```text
MCI / Rightel SSH client
       |  TCP customer SSH service (2252)
       v
Public Edge relay (DNAT)
       |  WireGuard
       v
Core SSHD and authentication
```

The operator reports Core SSHD, Edge relay, DNAT counters, and Edge–Core WireGuard were functioning during the incident. That supports — but does not prove — absence of intermittent server or forwarding faults.

| SSH protocol stage / observation | MCI (affected) | Rightel (comparison) |
| --- | --- | --- |
| TCP connect | Reached | Reached |
| Server SSH identification/banner | Reached | Reached |
| KEXINIT / key exchange | Reached | Reached |
| NEWKEYS | Reached | Reached |
| EXT_INFO | Received in cited traces | Received in cited traces |
| SERVICE_ACCEPT | **Not observed before timeout** | **Observed** |
| Authentication phase | Not reached in cited trace | Reached; deliberate invalid `probe` user denied |
| Functional NPV application traffic | Customers reported unable to connect | Working access operator-reported; no matched NPV packet trace attached |

**Observed failure class:** SSH protocol progression stopped **after KEX/NEWKEYS/EXT_INFO and before SERVICE_ACCEPT** on the affected MCI path. This is **not** a TCP-connect failure and **not** evidence that authentication credentials were invalid.

**Caveat:** `EXT_INFO` is an optional extension message; a future device must not require it as a mandatory success criterion. Reaching `SERVICE_ACCEPT` proves only SSH service readiness, **not** successful authentication, SSH forwarding, SOCKS functionality or NPV app traffic.

### 3.1 Paired packet-capture finding — reported, not independently re-analyzed

- Client capture: **34 packets**; Edge capture: **18 packets**.
- Edge-to-client payload: TCP sequence **2187604102**, data length **492 bytes**.
- Client-side ACK recorded: **2187604594**, i.e. `2187604102 + 492 = 2187604594`.
- Subsequent client-side sends (reported as **16- and 60-byte** data packets) were visible at the Windows vantage.
- The reported Edge capture did **not** show the corresponding ACK or those follow-up client data packets; repeated retransmissions of the Edge-side segment were observed.

**Supported interpretation (conditional on capture completeness):** The client capture acknowledged reception of the Edge payload, while later client-to-Edge traffic was not seen at the Edge vantage. This points to a possible **client → Edge delivery or observation gap** after the SSH exchange progressed. It does **not** locate the loss or prove DPI. Capture-point selection, capture drops, filters, NAT/hotspot behavior, missing packets and time alignment must be reviewed before treating absence in one trace as definitive on-wire loss.

### 3.2 Operator/IP and transport controls

- The operator reports the **same Edge IP/SSHD/service port** reached authentication from **Rightel** while timing out from **MCI**. Client-impact and cross-ISP behavior support the *operational* label **selective filtering / reachability restriction affecting MCI**, but the mechanism remains **UNKNOWN**.
- The report describes **other Edge IPs** exhibiting the pattern at different times. This suggests target-IP and time dependence, not a proved blacklist algorithm, traffic threshold or history-based trigger.
- A **wstunnel v11.1.0 TLS/WebSocket transport** on the already-affected IP completed TCP/TLS/WS upgrade on MCI and received SSH identification, but subsequent SSH transport was unstable. Rightel advanced to `SERVICE_ACCEPT`. The first WebSocket test was proxy-confounded and excluded; later direct-path results cannot by themselves prove DPI recognized WSS.
- The 2026-10-22 state must **not** be assumed current for those Edge addresses. Any future field test needs a fresh same-time reference, no production server changes and explicit owner approval.

## 4. Independent Windows HTTPS negative/control experiment

**Network condition:** User reported MCI access, VPN disabled. `--noproxy "*"` disables curl's proxy selection, but **does not independently prove OS-level routing/absence of a system tunnel**. This experiment did not include a contemporaneous independent egress attribution.

1. Ordinary `www.youtube.com` resolution returned an **RFC1918 private IPv4** rather than a normal public YouTube frontend; TCP/443 to that address was refused. This is **consistent with DNS redirection**, but the responsible resolver, intermediary or network device is not independently identified.
2. Subsequent tests used `curl.exe --resolve host:443:ip` to bypass DNS for the named host while preserving HTTPS hostname/SNI and HTTP Host header.
3. Both target names were tested **against each of the same two public IPs**, with `--tlsv1.2 --tls-max 1.2`.

| Public third-party IP | SNI/Host | Result |
| --- | --- | --- |
| `142.251.151.4` | `www.google.com` | TLS/HTTP completed; **HTTP 200** |
| `142.251.151.4` | `www.youtube.com` | Schannel **`SEC_E_INVALID_TOKEN (0x80090308)`**, `curl (35)` before HTTP |
| `142.251.150.4` | `www.google.com` | TLS/HTTP completed; **HTTP 200** |
| `142.251.150.4` | `www.youtube.com` | Same Schannel TLS failure before HTTP |

For YouTube the logs show the TCP attempt followed by Schannel processing failure, implying a connection advanced far enough to attempt TLS; unlike the Google logs, they **do not contain a separate explicit `Connected` line**. Do not overstate packet-level TCP proof. TLS 1.2 did not resolve the failure on either YouTube IP; it completed successfully for Google on both.

**Interpretation:** Failure tracks the requested hostname under two fixed-IP controls, **consistent with name-dependent TLS-path interference**. Alternative explanations include server/frontend behavior and client TLS interactions. Do not label this proof of SNI-specific filtering without additional protocol and capture controls. These tests do not directly exercise SSH or NPV Tunnel.

## 5. DenaProbe hardware baseline and detection gap

At the time of this synthesis, **ESP32 DEVKITV1 firmware v0.0.4** was physically flashed. Owner observations confirmed a completed healthy `DNS → TCP/2252 → SSH identification` probe and a **steady blue GPIO2 LED**. An artificially induced disruption caused the LED to blink, **without a synchronized serial trace identifying which alert state was active**. The red power LED is not a programmable status LED; **no extra LEDs are desired**.

Current device behavior:
- Edge target is a **locally configured hostname**, refreshed by DNS; target IP is not pinned in source.
- `HEALTHY` LED currently means **last DNS/TCP/SSH banner chain passed**, *not* real NPV service health.
- Independent control on Edge probe failure is only **public DNS + TCP/443**, not HTTPS/TLS.
- The device **does not implement SSH KEX, SERVICE_ACCEPT, authentication or NPV data-path checks**.
- **No filtered/blocked-edge ESP32 serial audit is available.** Windows SSH and HTTPS findings cannot be re-labelled as board validation.

**Critical false-negative case:** Real users cannot connect; ESP32 still reports `SSH_ID_PASS` and blue `HEALTHY` because the restriction manifests **after** the identification banner.

## 6. Evidence-driven firmware design requirements (proposal, NOT implementation approval)

| Priority | Proposed diagnostic contract | Why / constraint |
| --- | --- | --- |
| P0 | Keep DNS, TCP/2252 and SSH identification as separate observations with duration/error | Preserve existing tested baseline |
| P0 | Rename/qualify status meaning in diagnostics: `SSH_ID_PASS` ≠ NPV usable | Avoid false-green interpretation |
| P1 — feasibility gate | Evaluate **real SSH transport** from ESP32 through KEX/NEWKEYS and positive `SERVICE_ACCEPT` | Matches reported failure boundary; not possible by reading banner bytes alone |
| P1 | SSH host identity must be validated via approved pinned key/fingerprint; mismatch **FAIL_CLOSED** | No insecure trust-on-first-use bypass |
| P1 | No SSH password, customer account, Core address, private key or login attempt in device | Public research safety; no secret-bearing probe |
| P1 | Distinguish `TCP_PASS / SSH_ID_PASS / KEX_PASS / SERVICE_ACCEPT_FAIL` with stage-specific timeout/reset/protocol errors | Avoid all-or-nothing healthy label |
| P1 | Record operator/vantage, route confidence, firmware version, timestamp, target **alias**, session ID and controls | ISP comparisons must not be inferred from a remote server |
| P2 — optional separate experiment | HTTPS TCP-vs-TLS with explicit IP, SNI/hostname and a known-good same-IP control | Useful for web filtering diagnosis; **not** a proxy for SSH verification |
| P2 | Cross-ISP paired runs, repeated observations and verified reference NPV app outcome | Only reference app/data can substantiate actual VPN usability |

**Firmware constraints:** ESP32-WROOM-32 resources, crypto/KEX implementation complexity, host-key pinning, memory/time budgeting, blocking I/O and connection timeouts require an **explicit feasibility review before code**. No assumption that an Arduino TLS client can speak SSH. `SERVICE_ACCEPT` is **not** sufficient to prove NPV’s authenticated data path. Keep the **single onboard blue GPIO2 LED**; use serial/staged results for detailed classification rather than suggesting extra hardware.

**Status vocabulary:** `PASS` (positively observed stage), `FAIL` (observed stage failure), `NOT_TESTED` (capability absent), `UNKNOWN` (missing/unreliable evidence). Keep `suspected_filtered` as a **hypothesis/operational note**, never a proved automatic verdict from one timeout. Multiple vantage points are not equivalent. Missing MCI samples must not be called healthy.

## 7. Acceptance gates before changing firmware

1. Read-only review of actual v0.0.4 code, available libraries/ESP32 memory headroom and secure host-key verification feasibility.
2. Agree on a bounded protocol-stage experiment **without credentials**, an explicit stage-result contract and failure handling.
3. Test unaffected Edge control and **contemporaneously affected** operator-specific Edge from the same identified vantage; record a matched reference application result, ideally with Rightel comparison.
4. Audit the raw `.pcap/.pcapng` captures privately if available; publish only approved redacted summaries.
5. Validate flashed board serial logs, latency, heap, LED response and repeatability; no conclusions from LED blink alone.
6. Only then consider detection semantics or future telemetry integration. **No bot/API/telemetry work, no production mutation, and no PR merge/deploy is authorized by this document.**

## 8. Scope / source cross-reference

- [DenaProbe methodology](002-AUDIT-METHODOLOGY.md) and [prior sanitized field observations](004-AUDIT-OBSERVATIONS.md).
- NVLBot historical incident on 2026-10-20 is a **different incident**: see `docs/HEALTH_INCIDENT_2026-10-20_MCI_EDGE.md` in the NVLBot repository.
- Related NVLBot **2026-10-22** capture-backed operator report is separately summarized in `docs/MCI_SSH_FILTERING_PACKET_AUDIT_2026-10-22.md` in the NVLBot repository.
- **No firmware, bot, network configuration, server, scheduler or database changes accompany this record.**
