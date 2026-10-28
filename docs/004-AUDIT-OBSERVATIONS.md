# DenaProbe — Network Audit Observations

**Evidence state:** Observed client output; sanitized for public repository. No raw SSH logs, private user names, personal paths, server address, or credentials are included.

## Observation A-SSH-01: Windows SSH to reference endpoint

- **Date:** 2026-10-28 (from captured remote login banner; exact local measurement timestamp not recorded)
- **Scenario:** Intended healthy baseline; operator MCI reported by experimenter, but Windows routing/ISP egress not independently verified in this log.
- **Reference endpoint:** Redacted SSH target, nonstandard TCP port (2252).
- **Client:** Windows OpenSSH 9.5p1; diagnostic verbosity enabled.
- **Sample size:** Two successive SSH connection attempts captured.
- **DNS:** Host resolved to an IPv4 address in both attempts.
- **TCP:** `Connection established` in both attempts.
- **SSH identification:** Server identification `SSH-2.0` received; remote OpenSSH 9.6p1 identified.
- **SSH key exchange:** KEXINIT sent/received; curve25519-sha256 chosen; SSH2_MSG_NEWKEYS sent/received.
- **Authentication:** `Authenticated ... using "keyboard-interactive"` in both attempts.
- **SSH session:** Interactive channel and shell request accepted, then the remote side closed the session; `Exit status 1`. Login output said the user's home directory was unavailable. This is an **application/account/session behavior**, not evidence of network-level blocking.
- **VPN functionality:** Not tested; interactive SSH success cannot establish NPV Tunnel SSH-Direct proxy/data transfer success.
- **Latency:** Handshake durations and TCP RTT **not measured separately**; transferred bytes and interactive close intervals from the client log are insufficient for an accurate connect-time baseline.
- **Other controls:** DNS/HTTPS independent control destinations not measured in this sample.
- **ESP32 correlation:** Not measured simultaneously with these SSH attempts.
- **Confidence:** High for DNS + TCP + SSH identification/KEX + SSH user authentication reaching the server through the Windows host's then-active network path. **Not yet enough** to label a verified MCI-only baseline or a working VPN session.

### Required next steps

1. Confirm Windows is connected to the Android `dena288` hotspot and uses the intended MCI mobile-data uplink, with local VPN/proxy disabled.
2. Attempt a **no-shell SSH session with local SOCKS forwarding** (where server policy permits), then verify actual HTTP(S) data through the proxy.
3. Independently confirm real NPV Tunnel SSH-Direct data transfer on a reference mobile client and run two independent HTTPS controls without the tunnel.
4. Repeat a minimum of three controlled healthy runs, with local timestamps and comparable observations for later failures.
5. Do not develop or validate a filtering classifier from these results alone.

### Privacy note

The initial log shared privately contained locally identifying details and connection metadata; it must **not** be copied wholesale into this public repository. The credential used in the experiment should be rotated/revoked after testing.


## Observation A-SSH-02: SSH dynamic forwarding / HTTPS response

- **Date:** 2026-10-28 (exact client timestamp and time zone not captured).
- **Client path:** Windows host -> SSH reference account (authenticated by keyboard-interactive) -> local dynamic SOCKS listener -> HTTPS request. Experimenter reported MCI hotspot connectivity; the Windows route/egress operator was not independently verified by this record.
- **OpenSSH dynamic forwarding:** `-N -T -D 127.0.0.1:1080`; SSH log confirmed listener and authenticated session.
- **Application test:** `curl.exe --proxy socks5h://127.0.0.1:1080 ... https://google.com`.
- **Observed result:** HTTP `301`, response body **220 bytes**, curl total request time **0.868949 s**.
- **SSH channel:** Dynamic `direct-tcpip` channel opened for `google.com:443` and later closed; closure by itself is not an error.
- **Interpretation:** Successful HTTPS response traversed the SSH SOCKS5 forwarding path in this one sample. `301` is a redirect, not a failed HTTP transaction. `time_total` is not network RTT, SSH handshake latency, or throughput.
- **Unverified:** Following the redirect to a final page, data throughput, long-lived stability, UDP/UDPGW, NPV Tunnel actual behavior, the routing of Windows over MCI rather than another network, and independent no-proxy controls.
- **DNS nuance:** `socks5h://` asks the SOCKS proxy side to resolve the HTTP target name; this does not establish that the Windows local DNS resolver could resolve `google.com`.
- **Next step:** Compare an ordinary HTTPS request without proxy under otherwise identical Windows / MCI conditions; then repeat via SSH and compare, recording outcomes and elapsed times.



## Observation A-HTTP-03: Direct versus SOCKS curl on 2026-10-28

- **Request:** `https://google.com` (no redirect following; HTTP 301).
- **Direct:** `curl.exe --noproxy "*"` with 10 s connect / 25 s overall timeout. Result **HTTP 301**, **220 B**, `time_total=0.868761 s`.
- **Via SSH:** `curl.exe --proxy socks5h://127.0.0.1:1080` with equivalent timeouts. Result **HTTP 301**, **220 B**, `time_total=0.868949 s`.
- **What this shows:** Both tested client paths produced HTTP responses; the SSH log independently shows a SOCKS dynamic-tcpip channel for `google.com:443`.
- **What it does not show:** A meaningful performance difference (one observation each); identical response body (only byte counts match); MCI-only path attribution; no Windows OS-level VPN; that NPV Tunnel/UDPGW works. `--noproxy "*"` skips curl proxy configuration but is not a bypass for VPN network interfaces or network-wide tunnels.
- **Next check:** With OS-level tunnel disabled and Windows attached to the Android MCI hotspot, compare public egress IP for direct versus SOCKS requests. Avoid committing full logs, client identifiers or public IPs without review.



## Observation A-ROUTE-04: Egress network attribution failed (2026-10-28)

Two HTTPS IP-echo requests from the Windows host:
- `curl --noproxy "*"`: A public IPv4 in **144.172.68.0/24**.
- `curl --proxy socks5h://127.0.0.1:1080`: A different public IPv4 matching the remote SSH host's observed network address.

Independent public BGP and IP registration lookups describe the **144.172.68.0/24** origin as **AS30823 aurologic GmbH**, registered to **RouterHosting LLC / Cloudzy**, a cloud/hosting network rather than the MCI mobile carrier. These results are *inconsistent* with direct unmodified MCI carrier egress. (Example public references: `https://ipgeolocation.io/browse/ip/144.172.68.69`, `https://www.bigdatacloud.com/network-lookup/144.172.68.0/24`.)

**Interpretation:** Distinct proxy and non-curl-proxy egress IPs are confirmed, but **the intended no-VPN MCI baseline is not verified** and is likely confounded by an OS/network tunnel or alternate active uplink. Note that `--noproxy "*"` only bypasses curl's proxy settings; it cannot disable a system-wide VPN/TUN route.

**Next step:** Disable OS-level tunnel and proxies temporarily for the controlled run; ensure the Windows active Wi-Fi is the Android MCI hotspot; recheck **no-proxy** public IP/ASN and route selection. Avoid private or server IPs in published audit records.


## Observation A-MCI-TCP-05: First no-VPN MCI egress and TCP connection (2026-10-28)

- **Experimenter condition:** Previous system VPN/tunnel was disabled; Android hotspot uplink was reported as MCI.
- **No-curl-proxy public egress:** IP was in **95.64.64.0/18** (exact dynamic customer IP intentionally redacted); that network range is registered to MCCI / **AS197207**. Public sources: https://www.ipregistry.co/AS197207 and https://www.ipxo.com/ip-info/95.64.107.155/24/ .
- **DNS resolution:** Windows resolved the user-approved SSH host to an IPv4 destination.
- **TCP connect:** Windows `Test-NetConnection -Port 2252 -InformationLevel Detailed` returned `TcpTestSucceeded : True`.
- **Windows source interface:** `Ethernet 2`, source in RFC1918 range; private next-hop in RFC1918 range. Could be USB tethering or virtual adapter: **interface type not verified**. Do not silently equate this Windows route with ESP32 Wi-Fi hotspot path.
- **Interpretation:** MCI ASN egress together with successful DNS and TCP are observed. SSH banner/KEX/authentication, proxy traffic, independent controls, NPV client outcome and exact Windows route-interface identity are **not yet measured on this corrected MCI path**.
- **Prior results:** Earlier SSH login and SOCKS5 HTTPS successes were recorded while OS tunnel was on; those outcomes cannot serve as a controlled MCI baseline.

