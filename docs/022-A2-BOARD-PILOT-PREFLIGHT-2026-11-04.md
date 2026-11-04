# DenaProbe — A2 ESP32 field pilot preflight / auth-only mode
**Started:** 2026-11-04
**Status:** PRE-FLIGHT PREPARED; NO PHYSICAL BOARD DATA YET; NO FLASH AUTHORIZED BY THIS DOCUMENT
**Parent:** 017 scope; A1 merged PR #15.
**Target:** ESP32 DevKitV1 Wi-Fi hotspot; Windows workstation. Core/Telegram/SSH server remain untouched.

## Why the A2 auth-only safety guard exists

The original A1 Deep experiment opens direct-tcpip forwarding immediately after successful authentication. Until the operator independently verifies the terminating SSH host, host-key fingerprint and forwarding permissions, that is premature.

- New PROBE_DEEP_AUTH_ONLY defaults to 1 when Deep is compiled. Authentication can succeed on the real board while CHANNEL, TRANSFER_1 and TRANSFER_2 report NOT_TESTED; no forwarding channel is opened.
- DPT/2 z.s remains 90 (unknown/data-plane untested), not 1 (two verified data samples). The local Serial message independently reports AUTH_SUCCESS/REJECTED/TIMEOUT/ERROR.
- The existing A1 two-body synthetic tests opt in to transfer-mode explicitly; no wire codec or Core classifier changes.
- The dedicated PlatformIO environment esp32dev_a2_auth_only_compile builds the safe pilot, and rejects a conflicting local header at compile time (Deep=1, Password=1, AuthOnly=1 required). The pilot additionally asks libssh for only ssh-ed25519 host keys before connecting; a mismatched SHA256 pin still fails closed before credentials. The exact ED25519 fingerprint and actual password method must be checked independently by the operator before flash. Do not upload the generic A1 password compilation target for the first A2 test.

## Gate 1 — read-only board baseline (Windows PowerShell)

Capture the CURRENT running board Serial before resetting it for a flash read. Close with Ctrl+C; preserve a redacted baseline of reset reason, TCP/SSH, HTTPS and DPT status. Do not upload secrets or complete flash images:

~~~powershell
pio device monitor -p COM6 -b 115200
~~~



Close every serial monitor before invoking esptool. With the repository checkout on master and the board connected:

~~~powershell
git switch master
git pull --ff-only
git rev-parse HEAD
git status --short
pio device list
python -m esptool version
python -m esptool --chip esp32 --port COM6 flash-id
~~~

COM6 is the previously used port; replace it if device listing shows another. Install esptool with python -m pip install "esptool>=5,<6" only if absent.

Before flashing, keep a locally private full-chip readback. The .pio path is gitignored and must NEVER be attached to a chat, issue, pull request or shared log.

~~~powershell
New-Item -ItemType Directory -Force -Path .pio/a2-backups | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = ".pio/a2-backups/esp32-$stamp-full.bin"
python -m esptool --chip esp32 --port COM6 -b 115200 read-flash 0 ALL $backup
Get-Item $backup | Select-Object Name, Length
Get-FileHash -Algorithm SHA256 $backup
python ops/a2_partition_report.py $backup
~~~

The last command prints only partition metadata and capacity; capture it for review. If physical flash size is not 4MiB, the partition table is unreadable, the current app slot is too small or rollback cannot be retained, STOP. An upload of min_spiffs may rewrite the partition table and change SPIFFS allocation; never treat CI capacity as actual board capacity. Do not use erase commands.

## Gate 2 — independently verified SSH host key and permitted authentication

- Identify the actual SSH server endpoint reached through the same hostname and port as the NPV client on the same hotspot/operator. An Edge relay might not be the SSH termination host.
- An ordinary ssh-keyscan is UNTRUSTED until its fingerprint matches the host public key provided by a trusted operator or verified independently on the terminating SSH host. The existing known_hosts entry may be useful only if independently trusted.
- If a trusted OpenSSH server host-key public file is available locally, derive the raw-blob SHA256 hex expected by PROBE_SSH_PIN_SHA256_HEX:

~~~powershell
ssh-keygen -lf .\trusted-host-key.pub -E sha256
$line = (Get-Content .\trusted-host-key.pub | Where-Object { $_ -match '^(ssh-|ecdsa-)' } | Select-Object -First 1)
$blob = ($line -split '\s+')[1]
python -c "import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(sys.argv[1])).hexdigest())" $blob
~~~

Require a 64-character hex digest and match the actual negotiated server key, not merely a hostname. Never accept a new key from the network without independently validating its fingerprint.

- From an existing trusted Windows SSH client, use a single bounded password method with public-key and keyboard-interactive disabled; never supply the password as a command argument. Example pattern after verifying the host key:

~~~powershell
ssh -vv -N -T -p 2252 -o StrictHostKeyChecking=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no -o KbdInteractiveAuthentication=no -o NumberOfPasswordPrompts=1 YOUR_USER@YOUR_HOST
~~~

After a verified Authentication succeeded log line, Ctrl+C terminates the auth-only SSH client without requesting a shell. If the server only supports keyboard-interactive or refuses the account, classify AUTH_METHOD_UNVERIFIED / AUTH_REJECTED; do not silently downgrade the board behavior.

## Gate 3 — local secrets / collector consistency

- Preserve existing ignored include/probe_private.h and include/telemetry_private.h; do not replace working production telemetry settings with example placeholders. The real password, hostname and username are only provisioned locally, never in GitHub, Serial or CI.
- For the first A2 pilot explicitly configure: PROBE_DEEP_ENABLED=1, PROBE_DEEP_AUTH_MODE=1, PROBE_DEEP_AUTH_ONLY=1, verified PROBE_SSH_PIN_SHA256_HEX, PROBE_EDGE_HOST and PROBE_EDGE_PORT, PROBE_DEEP_USER and PROBE_DEEP_PASSWORD.
- The default DPT wire is 1 if not locally overridden. If existing Collector expects DPT/2, preserve the already validated version=2 + matching endpoint, device identity, key ID and HMAC configuration in ignored telemetry_private.h. Do not change server schema or issue a new key during A2 without approval.
- Check Wi-Fi hotspot details locally. Build credentials are embedded in the device flash; full-flash backups must stay private.

## Gate 4 — flash only after review / operator decision

Not part of preflight. Once gates 1-3 are evidenced and the pilot is explicitly accepted:

~~~powershell
pio run -e esp32dev_a2_auth_only_compile
pio run -e esp32dev_a2_auth_only_compile -t upload --upload-port COM6
pio device monitor -p COM6 -b 115200
~~~

Do not run these upload commands before hardware partition, host-key and account checks. Monitor AUTH status, authentication duration, heap/min-heap/largest block/stack watermark, Wi-Fi link stability, DPT FIFO and absence of CHANNEL attempts. Auth-only mode does not prove forwarding or NPV payload health.

## A2 recording / hold points

T01 current serial, D0 TCP preflight, HTTPS and signed telemetry baseline; T02 real Auth success and negative cases; T03 forwarding is deliberately NOT_TESTED in auth-only pilot; T04 two transfers/dwell NOT_TESTED until a pre-existing explicitly permitted target is confirmed; T05 Wi-Fi loss / host-pin mismatch must remain UNKNOWN; T06 target >=30 bounded authenticated sessions with no watchdog/reboot/heap decay; T07 same-operator NPV reference client baseline.

**Current result:** No serial log, physical ESP32 readback, verified target host-key pin, server auth method or forwarding authorization has been provided in this chat. A2 remains HOLD FOR PHYSICAL EVIDENCE. Core and Telegram Phase B may not start.
