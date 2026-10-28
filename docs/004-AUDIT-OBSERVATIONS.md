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

