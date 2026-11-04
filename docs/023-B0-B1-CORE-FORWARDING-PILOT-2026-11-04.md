# DenaProbe — B0/B1 controlled Core-loopback forwarding pilot

Date 2026-11-04. Status: SOURCE ONLY; no Core deploy, board flash or real forwarding test yet.

## Proven and pending

A2 real ESP32 SSH password login through Edge to Core: PASS. Owner approved proceeding. ED25519 host key was pinned; DPT/2 returned HTTP 200 and HTTPS eventually PASS. Thirty independent Deep logins and matched MCI/RighTel results are not yet established.

Witness path: mobile-hotspot Wi-Fi → Edge SSH front door → Core SSH termination → authenticated direct-tcpip → Core 127.0.0.1:18180 → known-body responder. This does NOT establish the actual customer SOCKS or public internet egress.

Companion source already exists: DenaSon/nvl-bot/ops/denaprobe_static_responder.py at nvl-bot master SHA 72ec395f61fa9ad4ecc82c7812e5c8d8d4acfc7c. It binds only 127.0.0.1, sends 16384 bytes of ASCII Z (0x5A) per connection then closes writing, and permits up to four active clients. Source existence is not production deployment.

## B0-A: read-only Core checks

On the server where SSH actually terminates (Core, not Edge), run:

~~~bash
sudo sshd -t && echo SSHD_CONFIG_SYNTAX_PASS
sudo sshd -T | grep -Ei '^(allowtcpforwarding|permitopen|disableforwarding|gatewayports|passwordauthentication) '
sudo ss -lntp '( sport = :18180 )'
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
python3 --version
~~~

Generic sshd -T is only an overview, not proof of a per-user Match rule. Do not change global SSHD, firewall, live NPV accounts, routes, PAM or customer credentials. If another service uses port 18180, HOLD.

## B0-B: temporary loopback responder; exact body/EOF test

Use a trusted local copy of the above specific pinned nvl-bot source file. If absent, stage that pinned source in an operator-controlled folder. Never download an unpinned script for privileged execution; run this one as a non-root process, foreground, not a systemd service:

~~~bash
python3 /path/to/denaprobe_static_responder.py --port 18180 --bytes 16384
~~~

In a second Core terminal, confirm binding is 127.0.0.1:18180 and check two connections and EOF:

~~~bash
sudo ss -lntp '( sport = :18180 )'
python3 - <<'PY'
import socket, time
for i in (1, 2):
    with socket.create_connection(("127.0.0.1", 18180), timeout=5) as s:
        s.settimeout(10)
        data = bytearray()
        while True:
            b = s.recv(4096)
            if not b: break
            data.extend(b)
        assert len(data) == 16384 and all(b == 0x5A for b in data)
        print(f"LOCAL_SAMPLE_{i}=PASS bytes={len(data)} EOF=YES")
    if i == 1: time.sleep(20)
PY
~~~

## B0-C: Windows → Edge → Core forwarding and per-user permission test

With responder running, in Windows PowerShell terminal A run a single command, supplying password interactively:

~~~powershell
ssh -N -T -p 2252 -L 127.0.0.1:18181:127.0.0.1:18180 -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no -o KbdInteractiveAuthentication=no -o NumberOfPasswordPrompts=1 YOUR_TEST_USERNAME@YOUR_EDGE_HOST
~~~

SSH local listener success is NOT proof that the remote direct-tcpip channel is permitted. Keep SSH open. In Windows PowerShell terminal B, run:

~~~powershell
@'
import socket, time
for i in (1, 2):
    with socket.create_connection(("127.0.0.1", 18181), timeout=5) as s:
        s.settimeout(10)
        data = bytearray()
        while True:
            b = s.recv(4096)
            if not b: break
            data.extend(b)
        assert len(data) == 16384 and all(b == 0x5A for b in data)
        print(f"EDGE_FORWARD_SAMPLE_{i}=PASS bytes={len(data)} EOF=YES")
    if i == 1: time.sleep(20)
'@ | python -
~~~

Ctrl+C in terminal A ends SSH. If a channel is administratively prohibited, refused or incomplete, if password auth fails, or if the host key mismatches: B0 HOLD. Do not relax global SSHD permissions automatically.

## B1 isolated firmware candidate (only after B0 PASS)

Uses the previously implemented password auth and real Core ED25519 host pin. Opens two separate direct-tcpip channels in the SAME authenticated SSH session, with 20s dwell and exact 16384 bytes 0x5A checked per sample. Firmware checks received bytes but does NOT independently verify EOF after the final requested byte; only the Core/Windows preflight checks EOF.

PRODUCTION CLASSIFIER SAFETY GATE: the existing nvl-bot detector.py maps z.s=30/31 (channel fail) to D1 and z.s=1 with both complete samples to HEALTHY; because this is Core-loopback, treating it as customer egress could cause misleading alerts/recovery. The B1 first physical pilot uses telemetrySafeResult: FULL Deep evidence is printed to Serial but OMITTED from on-wire DPT/2, while ordinary TCP/SSH/HTTPS measurements and ACK continue unchanged. The encoder fixture still proves future z/f/g contract with standalone synthetic results. DO NOT enable Core classification of B1 Deep or a signed Deep field pilot before a separately reviewed target/route isolation and alert policy.

New build: esp32dev_b1_forwarding_compile. It enforces Deep=1, Password=1, AUTH_ONLY=0, ED25519 host key algorithm, port 18180, 16KiB sample and 20s dwell at compile time. Existing deepSettingsValid requires remote 127.0.0.1. A2 and default builds remain unchanged. A local private header still saying AUTH_ONLY=1 must cause B1 build failure, not silent forwarding.

After B0-A/B/C PASS, keep approved Core responder running and update only the ignored local private header (do not expose credentials): set PROBE_DEEP_AUTH_ONLY=0; preserve all known-good Edge hostname, port, host key, test account, DPT/2 identity and CA. Confirm REMOTE_HOST=127.0.0.1, REMOTE_PORT=18180, SAMPLE_BYTES=16384, DWELL_MS=20000 and EVERY_N_CYCLES=2.

~~~powershell
cd D:\denaProbe\DenaProbe
git switch master
git pull --ff-only
notepad .\include\probe_private.h
pio run -e esp32dev_b1_forwarding_compile
~~~

Only after B0 PASS and reviewed build, manual board upload may be selected:

~~~powershell
pio run -e esp32dev_b1_forwarding_compile -t upload --upload-port COM6
pio device monitor -p COM6 -b 115200
~~~

Expected *future* Serial: HOST_KEY_PASS; AUTH_SUCCESS; TRANSFER_1 bytes=16384/16384 code=1; DWELL ~20000ms; TRANSFER_2 bytes=16384/16384 code=1; SUMMARY deep_code=1. In this serial-only first B1 pilot, DPT/2 continues carrying regular TCP/SSH/HTTPS with HTTP ACK but MUST NOT carry Deep z/f/g. Later signed Deep end-to-end evidence requires its own safe Core gate and build. Code 1 here proves only the Core-loopback controlled witness, NOT actual NPV egress or filtering causality.

Rollback/stop: kill foreground responder Ctrl+C, stop Windows SSH tunnel, preserve prior A2 auth-only image and private 4MiB flash backup; no erase, no SSHD changes. Stop on non-loopback bind, unauthorized forwarding, host pin mismatch, account rejected, watchdog/reset, repeated malformed or stalled data, heap erosion, or DPT failure. B2 Core classifier/Telegram is not part of this pilot.

Gates: A2 real auth + owner approval YES; B0 Core forwarding permission LIVE proof PENDING; B1 source/CI PENDING; B1 physical test NOT STARTED; B2 not started.
