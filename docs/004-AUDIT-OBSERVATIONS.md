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



## Observation A-MCI-SSH-06: SSH authentication and SOCKS listener (2026-10-28)

- **Context:** Experimenter disabled Windows system tunnel/VPN and previously observed a direct public IPv4 assigned to MCI/AS197207. This SSH attempt followed that route validation; a simultaneous interface/egress capture was not made.
- **Windows client:** OpenSSH 9.5p1, using `-v -N -T -D 127.0.0.1:1080 -o ExitOnForwardFailure=yes -o ConnectTimeout=10 -o PubkeyAuthentication=no` to a user-authorized SSH endpoint, TCP port 2252.
- **TCP:** Connection established.
- **SSH identification:** Remote SSH protocol 2.0 and OpenSSH 9.6p1 identification received.
- **Key exchange:** KEXINIT sent/received; `curve25519-sha256` negotiated; host-key type `ssh-ed25519`; `chacha20-poly1305@openssh.com` encryption. ECDH reply and NEWKEYS exchange completed.
- **Server authentication:** Previously known host-key matched the client's local known_hosts entry. This does not replace independent trusted fingerprint verification for new keys.
- **User authentication:** Successful using `keyboard-interactive`.
- **Local forwarding:** SOCKS listener bound to `127.0.0.1:1080`. No SSH shell requested.
- **Not yet verified:** That server policy permits a forwarded application connection, any HTTPS data through the SOCKS tunnel on this no-VPN MCI run, UDPGW, or real NPV Tunnel user-experience.
- **Status:** PASS through SSH user authentication and local SOCKS listener creation; data-path verification **pending**.



## Observation A-MCI-SOCKS-07: HTTPS request times out after successful SSH authentication

- **Date:** 2026-10-28; exact local timestamp not included in user-provided output.
- **Context:** Windows system tunnel reportedly off; previous curl public egress belongs to the MCI mobile network. Same OpenSSH tunnel from A-MCI-SSH-06 remains running; Windows route was not separately captured at the exact request timestamp.
- **SSH status immediately before test:** `Authenticated` via keyboard-interactive; dynamic local SOCKS listener bound to `127.0.0.1:1080`.
- **Request:** curl HTTPS to Google root through `socks5h://127.0.0.1:1080`, following redirects, `--connect-timeout 10`, `--max-time 25`.
- **Result:** `curl: (28) Connection timed out after 10015 milliseconds`; `HTTP=000`, `bytes=0`, `time_total=10.015116 s`.
- **SSH client events during request:** `Connection to port 1080 forwarding to socks port 0 requested`; `channel 1: new dynamic-tcpip`. The provided excerpt does **not** include a downstream `open confirm` for the forwarded SSH channel. This is insufficient to determine whether the hang was remote DNS lookup, the remote server's outbound TCP to the HTTPS destination, an SSH transport stall, an endpoint-specific issue, or a forwarding restriction.
- **Important contrast:** Earlier curl via SSH SOCKS succeeded from the Windows host **while a separate system-wide tunnel was still enabled**. Different underlay routes prevent attributing this difference to filtering without further controls.
- **Interpretation:** Successful SSH identification, KEX, password authentication and local SOCKS binding **do not prove** application data transport. This run exhibits a **forwarded HTTPS timeout**, not a proven MCI filtering event and not yet a confirmed NPV Tunnel failure.
- **Next diagnostic:** Keep SSH running and curl a *different independently reachable HTTPS destination* via the same SOCKS5 proxy with verbose output to identify whether SOCKS negotiation, SSH channel opening, TLS, or HTTP is the last observed stage. Follow with direct-path control from the same Windows interface and multiple repeat attempts.


## Observation A-MCI-SOCKS-08: HTTPS succeeds through SSH dynamic SOCKS forwarding (2026-10-28)

- **Context:** Same intended MCI mobile-data no-system-tunnel audit sequence as A-MCI-SSH-06/A-MCI-SOCKS-07. No new per-request upstream route check provided. The actual NPV Tunnel app was not part of this measurement.
- **Client:** Windows curl 8.13.0 with `-v --noproxy "" --proxy socks5h://127.0.0.1:1080 --connect-timeout 10 --max-time 25 -o NUL https://example.com/`. SSH `-N -T -D` listener remained active.
- **SOCKS:** Local SOCKS connection started, request to `example.com:443` with proxy-side hostname resolution; curl explicitly reported `SOCKS5 request granted`.
- **TLS:** TLS negotiation progressed; ALPN selected `http/1.1`.
- **HTTP:** Received `HTTP/1.1 200 OK` and **577 bytes** of response body.
- **Duration:** About **7 seconds** as indicated by curl's progress display, not an exact measured `time_total`. This is not an RTT or throughput estimate.
- **Interpretation:** A real application-data transfer via the SSH SOCKS path completed successfully in this sample. The earlier `google.com` SOCKS HTTPS attempt that timed out is **not** evidence of blanket SSH forwarding failure; it remains unexplained and may reflect a destination-specific or transient factor or a too-short timeout.
- **Still not tested:** Successful NPV Tunnel application data, UDPGW, persistent connection stability, multiple matched rounds, target failure-state comparisons.
- **Next test:** Retry `google.com` with verbose curl and a longer connection timeout, preserving the same tunnel and network conditions. Compare where it stops (SOCKS, TLS, HTTP) before attributing a cause.


## Observation A-MCI-SOCKS-09: Local SOCKS listener refused connection (2026-10-28)

- **Context:** After a successful `example.com` HTTPS transfer through SSH SOCKS (A-MCI-SOCKS-08), a later Google request was attempted with longer timeout.
- **Command class:** curl `--proxy socks5h://127.0.0.1:1080 --connect-timeout 20 --max-time 40`.
- **Observed error:** `curl: (7) Failed to connect to 127.0.0.1 port 1080 after 2045 ms: Could not connect to server`. Verbose output reported TCP **Connection refused** at the local proxy endpoint.
- **Interpretation:** The failure occurred **before SOCKS5 negotiation and before any destination/SSH forwarding request**. It cannot be attributed to Google reachability, MCI network filtering, or remote SSH server behavior from this log alone. Likely no process was listening on port 1080 at that moment; SSH tunnel may have terminated, but that cause is not yet independently confirmed.
- **Next diagnostic:** Use Windows `Get-NetTCPConnection -LocalPort 1080 -State Listen -ErrorAction SilentlyContinue` to inspect local listener; inspect the SSH window and re-establish the SOCKS tunnel as needed. Re-run endpoint tests only once the local listener is verified.


## Observation A-MCI-TLS-10: Google HTTPS TLS handshake fails after SOCKS grant (2026-10-28)

- **Context:** Windows SSH dynamic forwarding listener was confirmed reachable again. This observation followed A-MCI-SOCKS-08 (successful `example.com` HTTPS 200 through SSH). The experimenter reported Windows system VPN disabled and MCI mobile uplink, previously checked by public IP; not independently revalidated during this individual request.
- **Test:** curl verbose to `https://google.com/` with `socks5h://127.0.0.1:1080`, `--connect-timeout 15`, `--max-time 40`; local HTTP proxy disabled.
- **SOCKS result:** `SOCKS5 request granted`, so unlike A-MCI-SOCKS-09, the local SOCKS listener was active and the SOCKS CONNECT request succeeded.
- **TLS result:** curl reported `ALPN: curl offers http/1.1` followed by `schannel: failed to receive handshake, SSL/TLS connection failed`. No successful TLS handshake or HTTP response was observed.
- **Final curl error:** Exit error **35**, `HTTP=000`, `time_total=10.533483 s`.
- **Interpretation:** HTTPS TLS handshake failed **after** SOCKS CONNECT was granted. This is materially distinct from a failure to connect to local port 1080, from failed SSH user authentication, or from proof of blanket SSH transport blocking. The timeout or peer-close mechanism cannot be distinguished from this short log alone.
- **Alternative explanations to test:** Google-specific TLS endpoint behavior, destination/path route or DNS differences (remote SOCKS resolution may prefer IPv6), intermittent packet loss, SSH forwarding instability, or filtering. No particular cause is established.
- **Next discriminating control:** On the same Windows/MCI network, execute verbose `curl -4 --noproxy "*" https://google.com/` without SSH/proxy, capturing the stage and outcome; compare with SOCKS and independent example.com successful reference. Preserve exact conditions, timestamps, and repeated attempts.


## Observation A-MCI-TLS-11: Direct Google HTTPS succeeds (2026-10-28)

- **Context:** Windows system tunnel/VPN reported disabled and no-proxy public egress previously attributed to MCI/AS197207; direct IPv4 curl request.
- **Command class:** `curl.exe -v -4 --noproxy "*" --connect-timeout 15 --max-time 40 -o NUL ... https://google.com/`.
- **DNS:** Local resolver returned IPv4 `216.239.38.120` for `google.com`.
- **TCP/TLS:** Connected to TCP 443; completed TLS handshake, negotiated ALPN `http/1.1`, displayed a Google Trust Services-issued certificate for Google domain.
- **HTTP:** `301 Moved Permanently` to `https://www.google.com/`; 220 bytes received. `time_total=0.877814 s`.
- **Contrast with A-MCI-TLS-10:** Google direct HTTPS succeeded while a separate HTTPS attempt through SSH dynamic SOCKS using `socks5h` failed during TLS negotiation. A working SSH/SOCKS connection to independent `example.com` was also observed. These experiments do **not** prove filtering: endpoint-specific resolution, remote SSH server egress, IPv4/IPv6 selection, and transient conditions differ. Only one directly comparable attempt per path was measured.
- **Next diagnostic:** Keep the same SSH tunnel active and compare `socks5://127.0.0.1:1080` (local DNS resolution with IPv4) to prior `socks5h://` (server-side DNS resolution). Record remote endpoint selection behavior and exact failure stage.


## Observation A-MCI-TLS-12: Local DNS/IPv4 SOCKS control also fails at TLS (2026-10-28)

- **Context:** Experimenter reports multiple users simultaneously unable to use SSH-based VPN connections, including Telegram updates through their VPNs. These are **unverified user reports**, not independently measured NPV reference-client failures. Windows VPN reported disabled and MCI direct egress previously checked.
- **Command class:** Windows `curl.exe -v -4 --noproxy "" --proxy socks5://127.0.0.1:1080 --connect-timeout 15 --max-time 40 -o NUL` with HTTPS to `google.com`.
- **Local DNS:** `google.com` resolved to IPv4 `216.239.38.120`. SOCKS5 sent an IP-address connection request to `216.239.38.120:443` (unlike earlier `socks5h` remote hostname lookup).
- **SOCKS:** Local port accepted connection and returned `SOCKS5 request granted`.
- **TLS:** curl offered `http/1.1` ALPN, but Schannel reported `failed to receive handshake, SSL/TLS connection failed`. Error 35, HTTP 000, 10.314569 s.
- **Paired contextual control:** Previous direct IPv4 curl to **the same Google IP** succeeded through TLS and got HTTP 301 in 0.877814 s. This reduces the plausibility of local DNS/IP selection as the sole explanation for these two client tests, but direct-MCI-to-Google and MCI-to-SSH-exit-to-Google use materially **different routes**, so no causal inference about the MCI SSH leg alone is warranted.
- **Interpretation:** In one sample, SOCKS TCP connect is granted while TLS application-layer exchange does not complete. The earlier success via SOCKS to an independent HTTPS site remains an important counterexample to blanket failure.
- **Possible causes, still unverified:** transient SSH payload stall, tunnel or exit-host network failure, destination-specific remote egress, packet loss, rate limiting, or selective filtering.
- **External context consulted 2026-10-28:** https://nabzz.online/iran-live showed provincial disruption signals in 19/31 provinces but no nationwide IODA-level outage, and https://filter.watch/english/2026/10/14/network-monitoring-september-2026-regime-fear-of-filtering-failure/ discussed fine-grained throttling that can elude high-level network health measurements. Neither establishes a causal explanation for this specific trace.
- **Next discriminating test:** Re-run HTTPS to previously working `example.com` through the *same persistent SSH SOCKS session*, while also tracking TCP listener status and SSH client debug output. Compare with Google failure under matched time conditions. Then test same reference SSH service via a different access network, and collect actual NPV Tunnel outcomes.


## Observation A-MCI-MIXED-13: Intermittent destination outcomes through SSH SOCKS (2026-10-28)

- **Context:** Experimenter still running intended no-system-VPN MCI audit using Windows OpenSSH dynamic SOCKS on `127.0.0.1:1080`. Windows/phone egress was verified in an earlier run, not independently rechecked for each request. NPV Tunnel itself not directly tested by these curl requests.
- **Google repeat, local DNS IPv4:** curl `-4 --proxy socks5://127.0.0.1:1080` resolved the same Google IPv4 as the earlier failing trial. SOCKS5 CONNECT was granted, TLS completed and HTTP `301` returned with 220 bytes; `time_total=4.670277 s`. Previous comparable Google tests had failed at TLS after SOCKS grant. **Outcome varied across time**.
- **example.com repeat, local DNS IPv4:** curl resolved `172.66.147.243` and `104.20.23.154`, and tried SOCKS CONNECT to `172.66.147.243:443`. No `SOCKS5 request granted` message was received. `curl: (28) Connection timed out after 15005 milliseconds`, `HTTP=000`, `time_total=15.009215 s`. A previous example.com request via **socks5h** had succeeded with HTTP 200 and response body; hostname-resolution mode and possible destination IP differed between those trials.
- **Interpretation:** Observed differences by request, time, and/or target network route. The example.com failure occurred *before completing the SOCKS CONNECT operation*; the previous Google TLS failure occurred *after* SOCKS CONNECT was granted. Do **not** label either as proven carrier filtering, DPI, traffic throttling, or blanket failure of SSH; remote server egress and timing remain confounders.
- **Next discriminating measurement:** Pair a direct (no proxy) HTTPS control to the exact resolved example.com IPv4 with a SOCKS HTTPS request in the same time window, keep endpoint IP fixed and examine the SSH client for channel-open errors. Repeat and time-stamp runs before deriving reliability metrics.


## Observation A-MCI-HTTP-14: Direct pinned-IP example.com control succeeds (2026-10-28)

- **Context:** Windows VPN reportedly disabled and direct public egress previously attributed to MCI; same investigation period as A-MCI-MIXED-13. Actual access interface/egress not rechecked during this request.
- **Request:** Windows curl `-4 --noproxy "*" --resolve "example.com:443:172.66.147.243" --connect-timeout 15 --max-time 30` for `https://example.com/`. DNS-to-IP mapping was pinned while retaining URL hostname for TLS.
- **Result:** HTTP **200** from `172.66.147.243`; TCP connect elapsed **0.138101 s**; cumulative TLS completion time **0.427458 s**; total request **0.603121 s**.
- **Contrast:** An earlier SSH SOCKS5 request for the same target IP timed out after 15 s *before* `SOCKS5 request granted`. These requests were not simultaneous. A successful direct connection does **not** locate the cause of the forwarded failure: the path from the remote SSH server to destination differs from the client direct route.
- **Next test:** Pin the same target IP using `--resolve` while proxying via `socks5://127.0.0.1:1080`, with the persistent SSH tunnel active, and capture the stage and timing. Repeat matched pairs and collect SSH client channel diagnostics as needed.


## Observation A-MCI-TLS-15: Pinned-IP example.com SOCKS grant followed by TLS timeout (2026-10-28)

- **Context:** Same intended Windows-over-MCI, system-VPN-off SSH SOCKS audit; immediately prior direct pinned-IP control A-MCI-HTTP-14 succeeded. Route/egress at request time not independently captured.
- **Test:** curl verbose via `socks5://127.0.0.1:1080`, with `--resolve "example.com:443:172.66.147.243"`, `--connect-timeout 15`, `--max-time 30`, HTTPS to `example.com`.
- **SOCKS:** Local DNS-cache pin was honored. `SOCKS5 connect to 172.66.147.243:443` and `SOCKS5 request granted` were observed at about the 2-second mark.
- **TLS:** Schannel offered HTTP/1.1 via ALPN, but the TLS handshake did not finish before curl's 15-second connection timeout. Error `curl: (28) Connection timed out after 15008 milliseconds`, HTTP `000`, total time **15.014325 s**. `time_connect=0` and `time_appconnect=0` are incomplete timing metrics for this failed proxy transfer and do not demonstrate that SOCKS connect was rejected.
- **Paired direct control:** Same target address and hostname received HTTP 200 with direct curl in **0.603121 s** (earlier sample; not concurrent).
- **Interpretation:** The previous SOCKS grant indicates the proxy-level connect stage was acknowledged, but end-to-end TLS did not finish on this attempt. The apparent 15-second cutoff is **client-configured connect-timeout**, not evidence of a 15-second network block. The distinct remote SSH egress path, transport stalls, route changes, target and server policy remain alternatives.
- **Next discriminating test:** Using the **same pinned IP**, compare unencrypted HTTP on port 80 *through the same SOCKS tunnel* to see whether any proxied application response can arrive without TLS. This is an additional port/protocol control, not an identical reproduction of HTTPS 443; a success or failure cannot prove a filtering mechanism. Continue to collect repetitions and remote server/network controls before designing ESP32 classifier.


## Observation A-MCI-HTTP-16: Pinned-IP plain HTTP succeeds over SSH SOCKS5 (2026-10-28)

- **Context:** Windows client using an existing local SSH dynamic SOCKS5 listener at `127.0.0.1:1080`; intended cellular MCI underlay, with system-wide tunnel reportedly off. The exact public egress and Windows interface were not revalidated during this request. This was an HTTP port-80 diagnostic control following the HTTPS port-443 timeout in A-MCI-TLS-15.
- **Test:** curl with `-4 --noproxy "" --proxy socks5://127.0.0.1:1080 --resolve "example.com:80:172.66.147.243" --connect-timeout 15 --max-time 30` targeting `http://example.com/`.
- **Observations:** Curl confirmed local DNS-cache pin; `SOCKS5 connect to 172.66.147.243:80` and `SOCKS5 request granted`. HTTP GET sent through the proxy and `HTTP/1.1 200 OK` received, with **577 response-body bytes**, `time_total=0.886396 s`.
- **Interpretation:** The active SSH SOCKS forwarding path demonstrably transported real application request and response data on this sample; SSH authentication alone is not the sole positive signal. The immediately preceding HTTPS port-443 sample to the same pinned IP failed after SOCKS grant while waiting for TLS, but differing ports/protocols and test timing prevent attributing the discrepancy specifically to TLS filtering, port-443 treatment, MCI, remote SSH egress or server state.
- **Next paired test:** Retry `https://example.com/` via the same SOCKS listener with `--resolve "example.com:443:172.66.147.243"` directly after this successful HTTP control, capturing verbose stage and timing. Collect repeated near-time comparisons and SSH debug channel signals rather than diagnosing filtering from a single pair.


## Observation A-MCI-SOCKS-17: HTTP works but HTTPS SOCKS CONNECT times out on same SSH session (2026-10-28)

- **User clarification:** The *remote SSH service port configured in user clients* is **2252**. The Windows diagnostic uses SSH `-p 2252` with a local dynamic SOCKS listener on `127.0.0.1:1080`. The `80` and `443` in the curl tests are **destination ports**, not SSH service ports. Both HTTP/HTTPS SOCKS tests traverse the same outer SSH port 2252.
- **HTTP control:** User pasted the same prior `example.com:80` output as in A-MCI-HTTP-16 (HTTP 200, 577 bytes, 0.886396 s). **Do not count it as a separate additional successful run.**
- **New HTTPS attempt:** Windows curl via `socks5://127.0.0.1:1080` with `--resolve "example.com:443:172.66.147.243"`, `--connect-timeout 15`, `--max-time 30`. Output: `SOCKS5 connect to 172.66.147.243:443`; **no** `SOCKS5 request granted`; error `curl (28) Connection timed out after 15005 milliseconds`, HTTP 000, total 15.009696 s.
- **Stage comparison:** A-MCI-TLS-15 had received `SOCKS5 request granted` for the same fixed IP:443 and then failed during TLS; **this** test did not complete SOCKS CONNECT at all. A-MCI-HTTP-16 on port 80 succeeded, and direct HTTPS to the same IP succeeded in A-MCI-HTTP-14. The variation in failure stage suggests intermittent or destination-port-dependent behavior, **not** a proved carrier filter or SSH-port-2252 block.
- **Still unresolved:** The remote SSH server's outbound TCP path and any server-side TCP/connect diagnostics, SSH channel-open failures, and the underlay route at the precise test time. SSH data delivery and remote egress cannot yet be separated.
- **Next diagnostic action:** Inspect the currently-running Windows OpenSSH verbose console after a failing SOCKS attempt, looking for `channel ... open failed`, `connect failed`, disconnects, or a stalled channel. Do not share passwords, keys, or other secrets.


## Observation A-MCI-SSH-18: Repeated transport resets in full SSH client log (2026-10-28)

- **Evidence:** A user-supplied extended Windows OpenSSH `-v -N -T -D 127.0.0.1:1080` debug transcript for the SSH service on destination port **2252**, together with the already recorded HTTP:80 success and HTTPS:443 failure outputs. The latter curl outputs are repeats of A-MCI-HTTP-16 and A-MCI-SOCKS-17 and must **not** be counted as new independent HTTP/HTTPS runs.
- **SSH transport:** At least **five** instances of `client_loop: send disconnect: Connection reset` appear after various established SSH sessions, plus one `ssh_dispatch_run_fatal: Connection to [redacted host] port 2252: Connection timed out` during a separate authentication-stage attempt. These observations support **unstable SSH session/underlying transport behavior** at some times. Without packet captures or timestamps they do not identify which endpoint sent a TCP RST, establish the time correlation to specific curl failures, or distinguish carrier disruption from local router, hotspot, SSH host or server-side faults.
- **Authentication:** Repeated SSH KEX and successful keyboard-interactive authentication events occurred. Other attempts displayed repeated `Authentications that can continue` without successful authentication, but the provided transcript cannot establish whether these were wrong credentials, account policy, or a network stall. Do not infer filtering from authentication retries.
- **Forwarded channels in latest logged session:** The client logged a SOCKS dynamic TCP/IP channel for an **HTTP port-80** target which subsequently closed, corresponding to the successful curl HTTP 200. A following dynamic TCP/IP channel was created for the next forwarded request, but the transcript ends without a channel open-success/failure or closure message. Other snippets showed an SSH channel for an HTTPS target later being freed; freeing itself does not say whether the HTTPS payload succeeded.
- **Interpretation:** The same service can complete SSH login and useful proxied HTTP data, yet shows intermittent whole-session resets/timeouts and forwarded HTTPS stalls. This is important evidence for separating **SSH control-plane success, SSH transport stability, per-channel open results, and application-data success** in DenaProbe. No filtering or DPI mechanism is proved.
- **Privacy:** The raw SSH transcript includes personal identifiers and sensitive machine paths/agent identity; **do not commit raw logs** or client account details. This note intentionally retains only sanitized observations.
- **Next action:** Restart the diagnostic SSH process using `-vvv` plus conservative `ServerAliveInterval` / `ServerAliveCountMax` values, then reproduce one pinned-IP HTTPS SOCKS attempt and capture timestamped failure-stage snippets in a future observation. Keep this control separate from direct egress and server-side testing.


## Observation A-MCI-RELAY-19: User reports recovery after relay switch; new healthy baseline required (2026-10-28)

- **User-reported event:** The experimenter changed the relay due to high latency. Afterwards, they reported that affected users' connection problems were resolved, and requested testing in a healthy, functioning state.
- **Critical environmental change:** Relay selection/topology changed. The exact old/new relay endpoints, routing changes, NPV client settings and any difference from the separately tested Windows OpenSSH reference server were **not provided**. Do not assume the relay changed the OpenSSH test server or the Windows underlay.
- **Evidence classification:** Qualitative user-reported operational recovery. This is **not** yet a controlled causal test showing that the prior relay was responsible or that MCI filtering ceased. Previous failed samples remain applicable only to their original measurement conditions.
- **Measurement design:** Start a separate post-switch *healthy baseline* series with renewed verification that the Windows no-proxy public egress uses the intended MCI mobile uplink, followed by independent control HTTPS, fresh SSH DNS/TCP/KEX/auth, SOCKS5 port-forwarding HTTPS, and true NPV Tunnel reference-client application traffic. Repeat healthy rounds rather than treating one success as proof of stability.
- **Sanitization:** No private relay URLs, credentials, user identity, host log, or full public client egress IP included.


## Observation A-POST-RELAY-EGRESS-20: Healthy HTTPS egress, but operator changed (2026-10-28)

- **Context:** The experimenter reported that changing a relay resolved the users' connection complaints. The current Windows no-proxy test was intended as the first post-switch healthy MCI baseline, but **its egress operator appears different from prior MCI evidence**.
- **Direct egress check:** Windows PowerShell 7.6.7, `curl.exe -4 -sS --noproxy "*" --connect-timeout 10 --max-time 20 https://api.ipify.org` returned HTTP **200**, total **0.657165 s**, with a newly observed public IPv4.
- **Network attribution:** The returned address falls within `89.32.104.0/21` announced by **AS57218**, registered as **RighTel Communication Service Company PJS**, not MCI's previously observed AS197207. External evidence (lookup of another IP in the same /21): https://whoisrequest.com/ip/89.32.105.120 ; overview of exact /24: https://ipinfo.io/ips/89.32.0.0/16 . Routing and allocation data do not definitively identify the user's actual physical SIM or rule out intermediate NAT, tethering changes or tunneling.
- **Classification:** Preliminary **RighTel-attributed direct egress** / possible alternate uplink. Do **not** label this as a confirmed healthy **MCI** baseline. The HTTP 200 response confirms only the no-proxy HTTPS reachability of the IP-check service, not SSH/NPV tunnel health.
- **Old vs new:** Previously verified no-system-VPN egress was attributed to MCI (AS197207). Because the relay was changed and the new egress appears to be from RighTel, prior failed MCI measurements and the present healthy request are **not a controlled like-for-like comparison**.
- **Next action:** Identify which SIM/mobile provider supplies the actual Windows hotspot/tether interface and whether the Windows system VPN or other tunnel is really disabled. Only then classify this as an MCI or RighTel healthy baseline and proceed with SSH/NPV controls.
- **Sanitization:** No exact client egress IP, hotspot details, credentials, or machine identity stored in this public note.


## Observation A-MCI-POST-RELAY-21: MCI-attributed direct egress restored for new healthy series (2026-10-28)

- **Context:** Following a user-reported relay switch and recovery of the affected VPN users, the Windows client briefly showed RighTel-attributed egress (A-POST-RELAY-EGRESS-20). The user now reports returning to Hamrah-e Aval (MCI) and provided an updated direct egress check.
- **Control:** Windows PowerShell 7.6.7 curl `-4 -sS --noproxy "*" --connect-timeout 10 --max-time 20` to `https://api.ipify.org`, returning HTTP **200** in **0.761895 s** and the **same IPv4 egress previously independently checked as MCI/AS197207**.
- **Evidence:** Positive direct HTTPS reachability, with egress address match to earlier MCI reference. HTTP-proxy bypass alone does not prove all OS-level tunnels or physical adapters are absent; the operator attribution rests on the prior identification and user's report of the current mobile uplink.
- **Classification:** **MCI-attributed post-relay healthy baseline candidate, Round 1 / egress checkpoint**. This is not yet confirmation that SSH transport, SOCKS forwarding, NPV Tunnel or UDPGW is working from the test computer. Operational restoration is user-reported and may involve a different relay/route from the Windows reference server.
- **Next diagnostic:** `Test-NetConnection n1.nvlsup.com -Port 2252 -InformationLevel Detailed` to verify DNS, Windows-selected interface/source route, and basic TCP reachability of the same historical reference SSH endpoint. Do not assume this is the newly changed relay without separate verification.
- **Privacy:** Exact client public IP excluded from public repository notes; no secret or full raw log included.


## Observation A-MCI-TCP-22: Post-relay SSH DNS target changed, TCP reachable (2026-10-28)

- **Context:** Post-relay healthy baseline candidate; the Windows user independently repeated the no-proxy public IPv4 check after briefly using an alternate (RighTel-attributed) route. The latest egress returned the same IPv4 previously attributed to MCI/AS197207; HTTPS IP-check returned HTTP 200 in 0.761895 s. The first, RighTel-attributed, output pasted in the same terminal buffer was a **previous result** and is not a concurrent measurement.
- **SSH endpoint change:** `Test-NetConnection` resolved the **same historical reference SSH hostname** to a **different IPv4 address** than before relay change. Previous target 45.61.180.119; new target 104.194.141.63. This is consistent with a changed DNS mapping/relay, but causal attribution to the user's relay modification is **unverified**. Exact endpoint IPs and login credentials are intentionally not retained in this public note.
- **TCP:** `Test-NetConnection [reference SSH hostname] -Port 2252 -InformationLevel Detailed` returned `TcpTestSucceeded=True`, confirming TCP reachability of **port 2252 on the newly resolved address**, not SSH authentication or forwarding.
- **Windows routing:** `InterfaceAlias=Ethernet 2`, source from the same private tether-like subnet as prior experiments, and a private next hop were recorded. Adapter naming by itself does not prove the physical tether method; the Windows-selected route was unchanged at the reported level.
- **Classification:** Healthy baseline **Round 1 — MCI-attributed direct egress and new-target TCP PASS**. Do not compare as a matched old/new relay causal test until controlling target address, underlay, timing and NPV application status.
- **Next control:** Start a new SSH SOCKS listener on an unused local port (e.g. 1081) and verify KEX, auth and listener for the **newly resolved endpoint** while leaving old port 1080 untouched; then test SOCKS HTTPS transport using this exact session.


## Observation A-MCI-SSH-23: New relay target SSH KEX and host-key PASS; authentication pending (2026-10-28)

- **Context:** Same post-relay, MCI-attributed healthy-baseline attempt after A-MCI-TCP-22, which found that the SSH hostname now resolved to a different IPv4 than in the earlier impaired period and TCP/2252 was reachable.
- **Windows test:** OpenSSH for Windows (verbose) attempting SSH noninteractive dynamic forwarding to local loopback SOCKS port **1081** with `-p 2252`, `ServerAliveInterval=10`, `ServerAliveCountMax=3`, `PubkeyAuthentication=no`.
- **Positive controls:** TCP `Connection established`; SSH protocol banner (OpenSSH 9.6p1 family), curve25519-sha256 KEX, ssh-ed25519 host key, chacha20-poly1305 cipher, `SSH2_MSG_NEWKEYS received`. The host's ED25519 key **matched the previously pinned known_hosts key for the same domain:port**, despite the DNS IP change. This supports the same trusted SSH host identity being presented, not proof of identical network topology.
- **Authentication:** Keyboard-interactive method offered a password prompt. Following **two user password attempts**, the server responded `Authentications that can continue: publickey,password,keyboard-interactive`, and a **third prompt remained open** at the end of the captured output. The account was **not authenticated in this transcript** and no dynamic SOCKS listener on port 1081 was confirmed.
- **Interpretation:** Transport, SSH identification and KEX succeeded; end-to-end SSH forwarding/HTTPS and healthy-reference client behavior remain **untested** in this new session. The re-prompts indicate rejection of the two prior authentication attempts, but do not establish whether the cause was credentials, account state, backend mapping, server policy or another factor.
- **Next action:** Do not repeatedly guess credentials or expose the password. Verify the appropriate authorized account credential in the user's secure source, then only if confident enter once at the pending prompt. If authentication succeeds, confirm `Authenticated` and `Local forwarding listening on 127.0.0.1 port 1081` before any curl test. If not confident, cancel with Ctrl+C and verify account access before resuming.
- **Privacy:** No raw credential, email, user account name, workstation path, or exact server IP included in this public note.


## Observation A-CORE-EDGE-24: Operator clarifies reference service topology (2026-10-28)

- **Operator-confirmed model:** NPV Tunnel client is configured with a domain whose A-record points to a **replaceable Edge**. Edge acts as public gateway/relay. **Core** manages SSH accounts and their authentication, and handles public internet egress on behalf of the clients. The Core address is not the intended public endpoint in client configuration.
- **Operational observation reported:** Edge endpoints are frequently affected by interference and replaced; a relay change reportedly restored users' application connectivity. Core was described as remaining hidden/unaffected, but that resilience is the operator's current observation and not proven by this audit.
- **Reinterpretation of preceding observations:** An A-record change for the same SSH hostname is consistent with switching the **Edge**, rather than switching the Core SSH server. An unchanged SSH host key is compatible with the same Core being reached through different Edges. Earlier references to 'SSH server egress' should be resolved as **Core egress** for this architecture, subject to validation that the tested Windows OpenSSH reference uses the intended Core backend.
- **Failure attribution:** SSH connect/KEX and local SOCKS success don't individually isolate failures in mobile-to-Edge, Edge-to-Core, Core authentication/forwarding, Core-to-destination, or application paths. Repeated connection resets, auth retries and SOCKS TLS timeouts should be evaluated against all of these domains, rather than assumed to indicate Edge or carrier filtering.
- **Baseline controls:** Tag tests by access operator, Edge epoch, Core back-end identity, SSH/NPV account status, and real NPV Tunnel data outcome. A changed Edge is a new test configuration. The SSH authentication attempts in A-MCI-SSH-23 were not successful as captured; that is an unresolved Core/back-end access issue, not proof the new Edge fails.
- **Privacy:** Do not add actual Core IP, relay internal routes, account identifiers, user secrets or raw logs to the public project.


## Observation A-MCI-NPV-25: Operator reports working NPV Tunnel after Edge change (2026-10-28)

- **Context:** Intended new post-Edge-switch healthy baseline for the Core/Edge SSH-based NPV Tunnel service. The Windows no-system-VPN egress IPv4 had just matched the previously verified MCI address. The same NPV hostname currently resolves to a different Edge address; TCP/2252 and SSH KEX/host key were observed to work. The separate temporary OpenSSH test account was **not authenticated** in the last captured attempt, so its SOCKS forwarding is **not yet verified in this new route epoch**.
- **Reference app:** In direct response to a request to verify the NPV Tunnel reference-client connection and actual Telegram message updates on MCI via the new Edge, the operator stated **"the connections are stable now."** Classify as **operator-reported healthy NPV application status**, not an instrumented success rate or measured packet-level proof of Telegram receipt. Do not infer which individual NPV modes (TCP forwarding/UDPGW/split tunnel) were tested.
- **Core/Edge attribution:** The operator states Edge has changed while Core serves SSH authentication/account management and public egress. Whether this specific device's traffic truly exits the same Core has **not** been verified by a new NPV-specific egress measurement.
- **Interpretation:** This is a valuable positive **reference-client healthy-state label** under the revised Edge. It should be tracked distinctly from the earlier impaired Edge and from previous Windows curl results; it is not evidence proving the prior interference cause or eliminating future filtering risk.
- **Next control:** From the **same phone while NPV is active**, check an independent public-IP HTTPS endpoint (e.g. api.ipify.org) and privately compare its returned egress against expected Core, rather than the underlying MCI carrier, provided browser traffic is actually routed through NPV. Do **not** publish the Core address or client identity in the public repo.


## Observation A-MCI-CORE-EGRESS-26: Operator reports persistent Core IP egress in NPV Tunnel (2026-10-28)

- **Context:** The operator had reported stable NPV Tunnel connections on the new Edge over MCI, and was asked to check an IP echo service in the same phone's browser with NPV Tunnel connected and browser traffic routed through it.
- **User response:** The IP shown is **always the Core public egress IP**, according to the operator. This is a **user-reported long-term operational observation**, not a fresh screenshot, packet-level verification, or counted repeated series in this turn.
- **Topological interpretation:** Consistent with the reported `client → replaceable Edge → Core → Internet` architecture: the DNS A record for the public SSH hostname targets the Edge; Core manages accounts/authentication and supplies final egress. Core IP persistence does not establish Edge/transport reliability in every session, nor independently prove that every app's traffic is forced through NPV.
- **Classification:** Qualitative healthy-reference **Core egress confirmed by operator report**. No public Core address, account IDs, or sensitive topology details committed.
- **Remaining baseline work:** Repeat independent HTTPS target loads from the **same phone with NPV connected** and a real application check, log whether responses actually arrive; keep Windows tethered direct egress tests distinct from phone tunneled egress. The prior Windows temporary SSH account has not successfully authenticated on the new Edge and should not be labeled as a passing SOCKS baseline.


## Observation A-MCI-NPV-27: Three user-reported fast HTTPS reloads via NPV, with baseline limits (2026-10-28)

- **Operator / reference client:** Under the current MCI + new Edge + existing Core setup, the user reports loading `https://example.com/` in a browser while NPV Tunnel is active **three times**, all successful and perceived as fast.
- **Classification:** Three qualitative **user-reported positive application-level observations**, not instrumented independent repetitions. Browser cache, service workers and reuse of existing connections were not controlled; no numeric load time or proof that each attempt freshly traversed the tunnel was captured. Do not treat these three reloads as a statistically measured success ratio, RTT or throughput.
- **Baseline significance:** Complements the operator's reported stable NPV connectivity and persistent Core egress in A-MCI-NPV-25 and A-MCI-CORE-EGRESS-26. The Edge has changed relative to pre-switch failure observations; so this is a different route epoch and does **not** independently establish which segment was responsible for the earlier instability.
- **Methodological review:** Additional ad-hoc page reloads or single curl requests now have diminishing diagnostic value. The major research need is *paired, time-aligned reference app status and sensor-observable measurements*. ESP32 presently only implements Wi-Fi association: it has **no** implemented DNS/TCP/SSH probes. A green NPV status does not mean that the unimplemented ESP32 diagnostics passed.
- **Next experiment/design phase (not implemented):** Instrument minimal ESP32 Wi-Fi RSSI/link, DNS result and time, independent TCP/HTTPS control if feasible, TCP connect and optional non-authenticated SSH identification (banner) to the current Edge:2252, with structured timestamps and error classes. On the same network, externally record NPV application working/failing as a ground-truth label. Avoid storing SSH passwords or Core IP, and do not claim censorship from a single failed probe. Only evaluate a detection rule after multiple matched working/failing captures; classify ambiguous scenarios as unknown/inconclusive.


## Observation B-ESP32-BUILD-28: Local v0.0.3 PlatformIO build successful (2026-10-28)

- **Operator environment:** Windows PowerShell, local repository on Windows, PlatformIO `esp32dev` target, Arduino framework. Local private Edge target configuration is present, but its contents and endpoint are intentionally not recorded in public GitHub.
- **Evidence:** Operator pasted the final `pio run` output, including successful compilation of framework objects, linking `.pio/build/esp32dev/firmware.elf`, ESP32 image creation, and terminal line `[SUCCESS]`.
- **Memory footprint from PlatformIO build:** static RAM reported as **46,968 / 327,680 bytes (14.3%)**; program image reported as **949,060 / 1,310,720 bytes (72.4%)** of the configured application partition. These figures are build-time estimates, not runtime heap usage or total physical flash capacity.
- **Classification:** Firmware **BUILD PASS**, with no reported compiler/linker errors. This does **not** prove USB upload, Wi-Fi association, DNS/TCP probes, SSH identification or operation on a physical ESP32.
- **Next:** Flash firmware to the connected ESP32 using `pio run -t upload`, then validate serial logs; keep serial monitor closed during upload and avoid posting unredacted infrastructure information publicly.


## Observation B-ESP32-FLASH-29: v0.0.3 upload reported successful (2026-10-28)

- **Prerequisite:** Local PlatformIO build for `esp32dev` v0.0.3 was previously successful (B-ESP32-BUILD-28).
- **User report:** The owner says the firmware upload to the physical ESP32 **completed successfully**. No uploader transcript or serial log was pasted in this turn.
- **Classification:** **FLASH PASS — operator-reported**, awaiting independent confirmation of the running image and successful Wi-Fi/DNS/TCP/SSH identification probing via serial output.
- **Next control:** Run `pio device monitor -b 115200` from the repository directory and record one complete `[probe] START` through `[probe] END` sequence; optionally reset the device to show its firmware banner. Do not publish raw serial output exposing the private Edge hostname/IP, network SSID, or other sensitive local-network details.
