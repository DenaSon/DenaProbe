# DenaProbe Telemetry Protocol — DPT/1

**Contract:** `DPT/1` · **Status (2026-10-31):** implemented experimentally in ESP32 R2-A + isolated Core R2-B; real signed transport field-tested; live-state hardening awaiting CI/hardware validation · **Owner:** DenaProbe ↔ NVLBot · **Language:** UTF-8; all machine codes are stable numeric values.

> **Scope boundary:** DPT transports observations from the ESP32 Wi-Fi / hotspot vantage point. It does not test NPV authentication, tunneled payload, Telegram delivery, LTE RSSI, cellular packet loss, or determine censorship. `SSH_SERVICE_ACCEPT_PASS` is not `VPN_OK`. Backend incident decisions are interpretations of multiple observations; the device never transmits an asserted filtering verdict.

This is the **single cross-platform source of truth** for the experimental firmware sender and isolated Core Collector; integration into NVLBot alerts remains unimplemented. Do not use C++ enum ordinals. The companion machine-readable files are:

- `contracts/dpt/v1/code-registry.json` — frozen wire values, independent namespaces;
- `contracts/dpt/v1/telemetry.schema.json` — structural payload validation (JSON Schema 2020-12);
- `contracts/dpt/v1/fixtures.json` — fictitious positive examples for both implementations.
- `contracts/dpt/v1/hmac-test-vectors.json` — exact public HMAC/SHA-256 signing test vector;
- `contracts/dpt/v1/ack.schema.json` — durable ingestion response schema.

Both sides MUST use the same released contract version and conformance fixtures. DPT/1 **is** now an experimental HTTPS Collector endpoint, firmware sender and dedicated SQLite journal; it is **not** a production NVLBot notification or filtering-decision service.

## 1. Normative vocabulary and invariants

**MUST / MUST NOT / SHOULD / MAY** carry their usual normative meanings. Unknown/newer **protocol versions** MUST be rejected (or safely quarantined) rather than silently reinterpreted. Unknown numeric **status/stage/HTTPS** codes within DPT/1 MUST be retained as `UNKNOWN(code)` and excluded from alert decisions, not interpreted as `PASS` or outage.

1. **Observation, not diagnosis:** distinguish what finished (`s`), the conservative final/stop stage (`p`), observed progress (`o`), and timing measurements. A bit marking a received packet does not prove cryptographic verification.
2. **Independent paths:** SSH probe and public HTTPS probe are separate sessions and separate conclusions. Missing HTTPS `h` means **no new HTTPS measurement in this event**, not pass, fail, or disabled.
3. **No stale masquerading as live:** distinguish measurement time, receipt time, last accepted sample and freshness. Never infer `WIFI_DOWN` or `SSH_FAILED` solely from silence.
4. **No physical identity leakage:** `id` is an opaque server-assigned ID, not MAC/IMEI; target `t` is an opaque registry ID, not a domain, port, IP, or private core address.
5. **Units:** all duration fields are **integer milliseconds**; `r` is ESP32-to-hotspot Wi-Fi RSSI in dBm; `h.n` is bytes. A measured `0` is not equivalent to an omitted/unmeasured field. **No bandwidth or LTE signal claim.**
6. **Immutable sample:** `(id,b,q)` identifies exactly one original event. Event JSON bytes are preserved for retries; mutable per-transmission uptime lives in a signed HTTP header, not in the event body.
7. **Device is an instrument:** it sends measurements and local fault codes, **not** translated Persian strings, severity scores, alert state, inferred root cause, LED mode, or `filtering_verdict`.

## 2. Transport

- Method: `POST`
- Path: `/api/dpt/v1/telemetry` (implemented by the isolated Core Collector behind the Cloudflare Tunnel; **not** a route within NVLBot).
- Scheme: **HTTPS only**, with normal certificate chain and hostname verification. No insecure TLS, plaintext downgrade, URL redirects, SSH passwords, or user account tokens.
- Content type: `application/json`, UTF-8. Compact serialization preferred, but **do not depend on JSON key order** for semantics. No floats, NaN, Infinity, comments, BOM, or duplicate JSON object keys.
- Device request body size: **maximum 1,024 bytes** (reject HTTP 413). A normal result should be a few hundred bytes; do not claim all cellular usage is only body bytes (TLS/HTTP overhead exists).
- One event per POST in v1. No batches, compression, persistent MQTT/WebSocket, server-issued commands or firmware OTA in this contract. Network timeouts and rate limits configurable on both sides.
- Platform choice for MVP: bounded JSON + HMAC. CBOR/protobuf is explicitly deferred until measured benefit justifies an incompatible major version.

## 3. Device-signed request authentication

Each device MUST have its own **random 256-bit HMAC-SHA256 secret** provisioned outside public Git and unique per `id`; server records an independent `key_id`. Key compromise/physical ESP32 extraction remains possible; secrets must never be printed, placed in URL, uploaded in telemetry, or committed to the repository. Support independent revocation and limited overlap during rotation.

Headers:

```http
Content-Type: application/json
X-DPT-Device: dp-lte-01
X-DPT-Key-Id: k1
X-DPT-Sent-Uptime-Ms: 19690200
X-DPT-Signature: <base64url-no-padding-of-32-byte-MAC>
```

Compute `body_sha` as **lowercase hex SHA-256** of the **exact raw UTF-8 HTTP body bytes**. Then compute the HMAC over the following ASCII/UTF-8 string, using LF (`\n`) separators and **no trailing LF**:

```text
DPT1
POST
/api/dpt/v1/telemetry
<device_id>
<key_id>
<sent_uptime_ms_decimal>
<body_sha_lowercase_hex>
```

`X-DPT-Signature` is unpadded base64url of the raw 32-byte HMAC. `device_id` and `key_id` are the literal validated header values, `sent_uptime_ms_decimal` is canonical base-10 unsigned decimal (no leading zeros except zero), and `body_sha` uses exact bytes. Reject duplicated signed headers, missing headers, noncanonical representations, header/body `id` mismatch, unknown/revoked keys, oversized body, invalid signature or malformed JSON. Verify MAC with a timing-safe comparison; do not return detailed authentication reasons to the client. HMAC verification MUST precede accepting a telemetry event. Method and path are signed to prevent cross-endpoint reuse.

**Cross-language golden vector (public test key only):** `contracts/dpt/v1/hmac-test-vectors.json` fixes exact raw JSON bytes, a synthetic 32-byte key (`000102...1f`), headers, the lowercase SHA-256 body hash (`79a60b9ea4807af5edc542105a25b119f7b4f93b8c257599f1ee847b1db145d3`), and the expected base64url signature `FvC6ftohQqvxpjiMdAQx-nCdsU3NccQdfZQKBGQpoBA`. Both firmware and NVLBot MUST reproduce that signature **byte-for-byte**, then demonstrate rejection when any signed input is changed. This fixture key is public and MUST NEVER be provisioned on a real device.

**Why uptime in a header?** `X-DPT-Sent-Uptime-Ms` is regenerated and signed for **every actual send/retry**, while the event body (and `id,b,q`) remains identical. If an event measured at `u=100000` is retried at send uptime `200000`, the backend can see that it was already at least 100 seconds old at transmission. This is a sender-reported age, not independently authenticated wall-clock time; server also records its own arrival time. Require `sent_uptime_ms >= u` and `>=h.u` if HTTPS `h` is present.

No assumption that the ESP32 has valid wall time is allowed. HTTPS certificate verification may require NTP; failure to synchronize means **no report should bypass TLS verification**. Buffer bounded events and declare telemetry delivery unavailable until trusted TLS can be established. Server-side `received_at` is authoritative for *arrival*, not necessarily *measurement*.

## 4. Wire message: fields

All root field names are ASCII, case sensitive; `additionalProperties=false` in the schema. Protocol version `v=1` is mandatory. Sample sequence numbers are unsigned **32-bit integers from 1**, strictly increasing across **all event kinds in a single boot**, not merely SSH test count. Reset `q=1` on a new boot ID. Overflows MUST start a new securely randomized boot ID (new BOOT event). Monotonic `u` uses extended **64-bit uptime milliseconds**, not the raw wrapping 32-bit `millis()`; preserve extended monotonicity across the runtime. JSON integer values MUST be exactly representable by all consumers (at most 2^53−1). A board reboot changes `b` and resets `q,u`.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `v` | uint | yes | Protocol major version, exactly `1` |
| `id` | string | yes | Server-assigned opaque device ID; 2–32 chars `[a-z][a-z0-9_-]` |
| `b` | string | yes | New cryptographically random **128-bit** boot identifier, 32 lowercase hex characters |
| `q` | uint32 | yes | Unique monotonic per-boot event sequence (all `k`) |
| `u` | uint64 | yes | Measurement/event completion uptime, milliseconds |
| `k` | uint | yes | Event kind: `1` probe, `2` local device event, `3` boot announcement |
| `t` | uint16 | on probe | Registered SSH target ID; mapping and revisions are server-owned |
| `w` | uint | on probe | Wi-Fi association `0 DOWN, 1 UP, 2 UNKNOWN`; never LTE |
| `r` | int | optional | Hotspot Wi-Fi RSSI in dBm, **only when `w=1`**; no fabricated 0 |
| `s` | uint | on probe/device event | SSH outcome or local device event code, with same registry |
| `p` | uint | on probe | Conservative stop/completion stage; `0` if unobservable |
| `o` | uint8 | on probe | Observation bit mask `0..255` |
| `d` | uint | optional | Time to resolve target DNS, only if attempted |
| `x` | uint | optional | SSH `ssh_connect()` transport duration, only if attempted |
| `a` | uint | optional | Time waiting for `ssh_service_request("ssh-userauth")`, only if attempted |
| `h` | object | optional | **A new HTTPS attempt performed during this result**; NEVER a cached previous result |
| `ts` | uint64 | optional | UTC UNIX epoch **milliseconds** at the event, only when clock is synchronized and validated |

`k=3 BOOT` MUST be the first event in a boot (`q=1`), announced with the same `id,b` before normal telemetry. It may be delivered late if the device was offline. It is an authenticated lifecycle marker, **not SSH reachability evidence**. `k=2 DEVICE_EVENT` MUST contain a local/event `s` code (`90..96` for this initial registry, later values are forward-compatible); no new SSH measurement is implied. For `s=96` (Wi-Fi link transition), `w` is mandatory. Unknown/newer local codes are stored without alert interpretation. `k=1 PROBE_RESULT` MUST have `t,w,s,p,o`. When `w=0` the board may create a local failure observation, but it cannot upload until Wi-Fi returns. Silence is not an explicit Wi-Fi-down event.

### New HTTPS subobject (`h`)

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `c` | uint | yes | HTTPS result code in independent HTTPS registry |
| `u` | uint64 | yes | HTTPS attempt completion uptime; separate from SSH event completion |
| `n` | uint | optional | Bytes actually received (0–65,536); measured only |
| `bt` | uint | optional | Body-transfer elapsed milliseconds; include only when measurable |
| `ms` | uint | optional | Total HTTPS test elapsed milliseconds |
| `ds` | uint | optional | HTTPS DNS elapsed milliseconds |
| `hd` | uint | optional | HTTP header completion elapsed milliseconds **including TLS and request** |
| `fb` | uint | optional | Time to first body byte from request start |
| `hc` | int | optional | HTTP response status, only if actually received |

`h.c=1` (PASS) and `h.c=2` (SLOW) require `h.n=65536` and a measured `h.bt`. For either, `h.ms` SHOULD be included. In the current firmware heuristic, `h.c=2` is a full 64 KiB transfer with `bt>=4000ms` (a **sample-specific suspicion**, not ISP-level throttling or bandwidth SLA); publish threshold and target configuration with firmware metadata. If HTTPS did not execute on this SSH cycle, **omit `h` completely**. If it executed but could not measure because of clock or memory, include `h` with code 11/12; do not fill unknown timing fields with fabricated zeros. The backend MUST derive current HTTPS freshness from the last **new** HTTPS attempt and receive/measurement history, not from repeated SSH events.

## 5. Immutable numeric code registry

**The companion JSON is authoritative for machines**; the Markdown tables below are a readable rendering. Code values never depend on C++ declaration order. Names are stable descriptive identifiers; translations belong to NVLBot.

### 5.1 Event kind (`k`)
| Code | Name | Meaning |
| --- | --- | --- |
| 1 | `PROBE_RESULT` | A completed SSH probe; optional new HTTPS result |
| 2 | `DEVICE_EVENT` | Local device/link/resource event, not a successful SSH test |
| 3 | `BOOT` | New boot ID lifecycle event |

### 5.2 Wi-Fi association (`w`)
| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `DOWN` | ESP32 disconnected from hotspot |
| 1 | `UP` | ESP32 associated with hotspot |
| 2 | `UNKNOWN` | Unknown/unmeasured, not DOWN |

### 5.3 SSH / local status (`s`)
| Code | Name | Conservative meaning |
| --- | --- | --- |
| 0 | `NOT_TESTED` | — |
| 1 | `SERVICE_ACCEPT_PASS` | Verified SSH service; never VPN login |
| 10 | `WIFI_DISCONNECTED` | ESP32-to-hotspot Wi-Fi, not cellular radio |
| 20 | `DNS_FAIL` | Edge DNS lookup failed |
| 30 | `SSH_TRANSPORT_TIMEOUT` | 12s transport deadline, stage ambiguous |
| 31 | `SSH_TRANSPORT_ERROR` | SSH transport returned an error |
| 40 | `HOST_KEY_UNAVAILABLE` | Could not verify server key |
| 41 | `HOST_KEY_MISMATCH` | Security/trust failure, NOT an ISP outage |
| 50 | `SERVICE_ACCEPT_TIMEOUT` | 8s SERVICE_ACCEPT deadline after trusted pin |
| 51 | `SERVICE_REQUEST_ERROR` | Service request returned an error |
| 90 | `RESOURCE_EXHAUSTED` | Local resource error, not network outage |
| 91 | `SSH_OPTIONS_ERROR` | Local configuration/library error |
| 92 | `WORKER_STALLED` | Watchdog-style worker stall: no SSH verdict |
| 93 | `CONFIG_INVALID` | Missing/invalid device config or pin |
| 94 | `QUEUE_ALLOC_FAILED` | Local queue allocation failure |
| 95 | `TASK_ALLOC_FAILED` | Local task creation failure |
| 96 | `WIFI_LINK_EVENT` | Wi-Fi link transition, may be buffered until reconnect |

Codes `0–51` are SSH-path outcomes or non-results. Codes `90–96` signal local setup/resource/worker/link conditions and MUST NOT be treated as network-path failures. A local SSH-abort inside a completed probe may use `k=1,s=90/91`; an independently reported device/worker issue uses `k=2,s=90..96`. In particular `HOST_KEY_MISMATCH` is a **security incident/trust failure**, not a generic ISP outage. `SERVICE_ACCEPT_TIMEOUT` is an observation, not proof that a specific network packet left the device or was censored.

### 5.4 Stage (`p`)
| Code | Name | Boundary/qualification |
| --- | --- | --- |
| 0 | `UNDETERMINED` | — |
| 10 | `WIFI` | — |
| 20 | `DNS` | — |
| 21 | `SSH_INIT` | — |
| 30 | `TCP_OR_SSH_BANNER_UNKNOWN` | TCP vs SSH banner remains unresolved |
| 31 | `BANNER_OBSERVED` | — |
| 32 | `WAIT_SERVER_KEXINIT` | — |
| 33 | `KEX_NEGOTIATION` | — |
| 34 | `KEX_OR_NEWKEYS_UNKNOWN` | — |
| 35 | `NEWKEYS_PROCESSING_UNKNOWN` | NEWKEYS callback observation is not processing proof |
| 40 | `HOST_KEY` | — |
| 50 | `SERVICE_REQUEST_OR_ACCEPT` | — |
| 51 | `WAIT_SERVICE_ACCEPT` | Transport and trusted host key completed; service response not accepted |
| 52 | `SERVICE_ACCEPT_RECEIVED` | SSH service accepted without login |
| 90 | `LOCAL` | — |

Stages indicate the deepest **conservatively inferable** state at completion. `p=30` intentionally merges TCP establishment and banner receipt when evidence cannot distinguish them. `p=35` does NOT imply NEWKEYS was successfully processed. `p=51` applies only after trusted SSH transport and host-key pin, and only when waiting for the accepted service response.

### 5.5 Observed milestones (`o`)

| Bit | Decimal value | Name | Evidence rule |
| --- | --- | --- | --- |
| 0 | 1 | `BANNER_PARSED` | Only if the corresponding libssh progress was actually observed |
| 1 | 2 | `KEXINIT_LOCAL_TX_PROGRESS` | Only if the corresponding libssh progress was actually observed |
| 2 | 4 | `KEXINIT_PEER_RX_PROGRESS` | Only if the corresponding libssh progress was actually observed |
| 3 | 8 | `KEX_ALGORITHMS_NEGOTIATED` | Only if the corresponding libssh progress was actually observed |
| 4 | 16 | `NEWKEYS_RX_OBSERVED_UNVALIDATED` | Non-consuming callback observation; not processing proof |
| 5 | 32 | `SSH_TRANSPORT_VERIFIED` | Set only after ssh_connect()==SSH_OK |
| 6 | 64 | `HOST_KEY_SHA256_PIN_VERIFIED` | Set only after SHA-256 pin comparison passes |
| 7 | 128 | `SERVICE_ACCEPT_RECEIVED` | Set only after ssh_service_request returns SSH_OK |

A bit set means that evidence occurred. A bit clear means **not observed**, not necessarily a failed protocol step. For healthy sessions `o=255` is common but NOT mandatory. The backend MUST NOT infer `o=127` from timeout by default; the device constructs it only from actual stage observations (including a verified pin). `SERVICE_ACCEPT` bit 7 MUST be unset for result `s=50`. `obs` cannot be used as a packet capture; `EXT_INFO` is not independently captured by current firmware.

### 5.6 Independent HTTPS status (`h.c`)
| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `NOT_TESTED` | — |
| 1 | `PASS` | Exactly 65,536 bytes; body under threshold |
| 2 | `SLOW_64K_SAMPLE_SUSPECT` | Full body but transfer >= configured 4,000ms in current firmware |
| 10 | `WIFI_DOWN` | Wi-Fi unavailable; not a Cloudflare verdict |
| 11 | `CLOCK_NOT_READY` | NTP clock unsuitable for certificate date checks |
| 12 | `LOW_MEMORY` | Local heap/fragmentation safety check |
| 20 | `DNS_FAIL` | Only Cloudflare hostname DNS failure |
| 30 | `TLS_OR_CONNECT_FAIL` | Endpoint-specific TLS/connect failure |
| 31 | `HTTP_SETUP_FAIL` | Local HTTP client setup error |
| 32 | `HTTP_STATUS_ERROR` | HTTP response not 200 |
| 40 | `BODY_ERROR` | Stream/read failure or timeout |
| 41 | `BODY_TOO_LARGE` | Body exceeds 64KiB |
| 42 | `BODY_INCOMPLETE` | Unexpected body length/incomplete |

### 5.7 Ingestion acknowledgement (`ack.r`)
| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `ACCEPTED` | New event durably stored |
| 1 | `DUPLICATE` | Exact duplicate of already stored event |
| 2 | `HISTORY_ONLY` | Durably stored as historical-only; never promoted to latest/live state |

**Reserved code policy:** codes in a namespace can be added only after code registry + schema + consumer tests are updated. Never repurpose, reorder, or reuse a released number. Adding a new code with identical field semantics is a backward-compatible minor registry revision **only if** consumers can ingest and retain unknown numeric codes without treating them as PASS or FAIL. Unknown values MUST be quarantined from alert evaluation until a registry update and tests are deployed. A field rename, changed meaning, changed unit, different signature or incompatible shape requires **DPT/2** and a new endpoint path.

## 6. Invariants and meaningful combinations

- `k=1, s=1` ⇒ `p=52`, `o` bits 5, 6, 7 set; authenticated SSH user login remains NOT_TESTED.
- `k=1, s=50` ⇒ `p=51`, `o` bits 5 and 6 set, bit 7 clear; indicates request/response phase timeout **after trusted host-key verification**.
- `k=1, s=41` ⇒ `p=40` and bit 6 **clear**; classify as trust/security concern. Do not retry against an untrusted key by bypassing validation.
- `s=30/31` ⇒ `p` derived from progress only; never claim a specific packet was blocked solely from elapsed time.
- `k=2` ⇒ no SSH measurement; backend MUST NOT overwrite last genuine SSH `k=1` sample with a made-up PASS or FAIL. It may record device health separately.
- Missing `h` ⇒ no new HTTPS measurement; last `h` is retained with original sample identity/time, then becomes STALE when old. Present `h` with `c=11` ⇒ attempted but unmeasurable.
- `r` is Wi-Fi signal strength; NEVER label it `LTE RSSI`. Carrier/MCI/RighTel attribution is server-configured deployment metadata, not an automatically sensed field.
- Never compute a filtering verdict, NPV tunnel pass/fail or Telegram health from only these fields.

## 7. Canonical example payloads (no secrets)

### 7.1 Successful probe with **new** HTTPS PASS

```json
{"v":1,"id":"dp-lte-01","b":"57fce203c6e94baf8d32749c11f0a65d","q":15,"u":423000,"k":1,"t":1,"w":1,"r":-38,"s":1,"p":52,"o":255,"d":52,"x":3337,"a":199,"h":{"c":1,"u":429000,"n":65536,"bt":2650,"ms":5941,"ds":46,"hd":3236,"fb":3240,"hc":200}}
```

### 7.2 Next 30s SSH probe **without** new HTTPS measurement

```json
{"v":1,"id":"dp-lte-01","b":"57fce203c6e94baf8d32749c11f0a65d","q":16,"u":453000,"k":1,"t":1,"w":1,"r":-39,"s":1,"p":52,"o":255,"d":1,"x":3298,"a":198}
```

The backend retains `h` from `q=15` with **its original timestamp**; it MUST NOT fabricate a second HTTPS sample at `q=16`.

### 7.3 Audit-like SSH SERVICE_ACCEPT timeout with trusted transport

```json
{"v":1,"id":"dp-lte-01","b":"57fce203c6e94baf8d32749c11f0a65d","q":17,"u":491000,"k":1,"t":1,"w":1,"r":-40,"s":50,"p":51,"o":127,"d":1,"x":3298,"a":8000}
```

This is a **hypothetical conformance fixture**, not proof that actual NPV filtering occurred. `o=127` says milestones 0–6 were observed and verified; no accepted service was observed. Client/network/server cause remains unknown.

### 7.4 Worker stall local event, **not** path failure

```json
{"v":1,"id":"dp-lte-01","b":"57fce203c6e94baf8d32749c11f0a65d","q":18,"u":550000,"k":2,"w":1,"s":92}
```

### 7.5 Boot announcement (mandatory on new boot)

```json
{"v":1,"id":"dp-lte-01","b":"8af37b68cf1d4662acd8d9512b70f305","q":1,"u":1250,"k":3,"w":0}
```

`id` and `t` values above are placeholders; boot IDs are fixture data, not real device secrets. Event `u` and optional HTTPS `h.u` are monotonic measurement-completion uptime in one boot. Example `X-DPT-Sent-Uptime-Ms` must be **at least** the latest event/subevent uptime.

## 8. Durable ACK, idempotency and delivery semantics

A server MUST answer success only **after the event is durably committed** (DB transaction). On success return HTTP `200` with:

```json
{"v":1,"b":"57fce203c6e94baf8d32749c11f0a65d","q":16,"ack":{"r":0}}
```

`ack.r`: 0=ACCEPTED, 1=DUPLICATE (identical immutable body), 2=HISTORY_ONLY. The ESP32 MUST verify the ACK's `v,b,q` match the pending item before eviction. If the network fails after server commit and before ACK, a retry MUST yield `ack.r=1`, not a second event.

Database uniqueness: `UNIQUE(device_id,boot_id,seq)`; persist **SHA-256 hash of immutable raw body**. Same key+same hash ⇒ duplicate. Same key+different hash ⇒ **409 CONFLICT**, security/data-integrity anomaly; do not overwrite. Signatures and sender-uptime headers may change between retries, but the event body MUST NOT. Sequence gaps are **missing evidence**, not implicit FAIL.

HTTP response handling:

| Response | Behavior |
| --- | --- |
| `200` with valid matching ACK | Evict buffered sample; update delivery statistics |
| `400/422` malformed / semantic-invalid | Quarantine/log locally; don't infinite-loop this sample |
| `401/403` unknown key, bad signature, revoked device | Stop aggressive retry; local config/security fault |
| `409` immutable identity collision | Stop; flag for operator investigation |
| `413` payload too large | Fix client; do not fragment silently |
| `429` / `5xx` / timeout | Exponential backoff + jitter, bounded retries / queue; honor `Retry-After` when reasonable |

Use a small bounded RAM queue. **R2-C hardening policy:** send retained events in strictly increasing per-boot sequence order (FIFO). Urgent failures **trigger early draining** but MUST NOT overtake older pending `q` messages. The first acknowledged BOOT precedes all results. On overflow, drop deterministically (oldest non-BOOT), increment a counter, preserve the numeric sequence gaps and NEVER relabel, fabricate or rewrite surviving immutable events. A bounded queue cannot guarantee lossless delivery; a gap must be treated as missing evidence, and confidence can recover only after new corroborating fresh SSH results. No per-30s flash writes in MVP; RAM loss on reset requires new BOOT. Do not retry indefinitely or call missing delivery an SSH failure. A device remains usable as a local monitor if the API is unavailable.

## 9. Backend storage, freshness, state and alert interpretation

Minimum logical entities (not final table migrations):

1. **devices:** `id`, enabled, key IDs and rotation status, deployment/carrier label (operator configured), accepted protocol versions, current boot.
2. **targets:** stable `t` ID with time-versioned server-side destination mapping and protocol configuration. Changing destination must create a configuration revision; never relabel old results.
3. **device_boots:** immutable `id,b` history, first/last seen, boot registration; retained long enough to prevent replayed old boots from being promoted as new.
4. **telemetry_events:** unique `id,b,q`, `k,s,p,o`, optional measurements, exact body hash, `received_at`, trusted/unknown `ts`, signed `send_uptime_ms`, computed sender age, history-only flag and validation version.
5. **device_latest_state:** materialized **derived** state, per channel, with original event keys, freshness and heartbeat/gap information; never overwritten by stale/out-of-order history.

**Freshness:** the current firmware expires SSH after ~90s and HTTPS after ~360s. These are **initial backend policy defaults**, not wire semantics. Compute per-channel freshness from **new measurements**. State dimensions: `ssh_path=PASS|FAILURE|LOCAL_UNMEASURABLE|STALE|NOT_TESTED`; `public_https=PASS|SLOW_SUSPECT|ENDPOINT_FAILURE|UNMEASURABLE|STALE|DISABLED|NOT_TESTED`; `delivery=ONLINE|STALE|OFFLINE_UNKNOWN`. Do not combine into an asserted VPN state. An HTTPS failure on Cloudflare is endpoint-specific.

**Ordering:** within an authenticated boot, only higher `q` of the correct event kind may advance that channel's latest measurement. A delayed lower sequence is history-only, not a recovery. A newly observed boot MUST have an authenticated `k=3` registration; a previously-seen boot ID MUST NOT reactivate an old boot. Once the backend is unsure about cross-boot order or freshness, mark `UNKNOWN/STALE` until fresh continuity is established; preserve history. Avoid trusting a raw client clock or a newly replayed boot marker as proof of recency.

**Live-alert eligibility:** sender age `sent_uptime-u` must be small, arrival recent, ordering/gaps validated, and there must be corroborating post-boot samples or an established recent heartbeat/continuity anchor. Device-reported `ts`, if present, is a supporting hint after clock validation; server `received_at` is measured independently. On cold start, clock uncertainty, offline backlog, reboot, or sequence discontinuity, prefer `UNKNOWN / MONITORING_GAP` to a false network alarm. Signed uptime alone **cannot prove delivery delay**; even valid HMAC events can be replayed. Avoid premature strong guarantees for sub-minute alerts.

**Rule examples (server-only, configurable):** (a) two consecutive eligible `s=30/31/50/51` within a recent window ⇒ `SSH_PATH_SUSPECT`; (b) `s=50,p=51` after trusted transport ⇒ `POST_KEX_SERVICE_ACCEPT_TIMEOUT`; (c) repeated `s=41` ⇒ security escalation, not connectivity outage; (d) `s=20` with independent DNS control ⇒ DNS-specific diagnostic; (e) fresh SSH PASS plus `h.c=2` ⇒ `PUBLIC_HTTPS_SLOW_SAMPLE`, not VPN slow; (f) no new telemetry ⇒ `DEVICE_STALE`, not SSH failure. Hysteresis, consecutive failures, rate limiting, notification cooldown and recovery-confirmation belong to a **later analysis-job phase**, not DPT/1.

**Delivery caveat:** the device cannot report a complete loss of its only Wi-Fi/upload path in real time. Silence is ambiguous; for exact ISP attribution, deploy multiple independent vantage points or operator-verified correlated observations.

## 10. Observability, translations and privacy

- Firmware MAY keep rich tagged Serial diagnostics, but the API MUST use frozen numeric DPT fields, not arbitrary Serial strings.
- NVLBot localizes code registry names into Persian/other languages in its presentation layer. Example: `s=1` → «اتصال SSH تا مرحله پذیرش سرویس موفق بود»; `s=50,p=51` → «پس از تأیید اتصال SSH، پاسخ پذیرش سرویس در مهلت مقرر دریافت نشد»; `s=92` → «پایشگر روی برد متوقف شده؛ وضعیت مسیر نامشخص است».
- Log sanitized IDs, numeric codes, timings, validation failures and request trace IDs; **never** HMAC secrets, full device credentials, hotspot credentials, end-user identifiers or raw private network endpoints.
- No collection of customer traffic, account passwords or payload bytes. Cloudflare sample body is discarded; only bytes/timing/results are transmitted.
- Device-side signal is 2.4GHz Wi-Fi-to-hotspot; carrier is a **declared** context, not automatically sensed. `filtering_verdict` is never a DPT/1 wire field.
- Raw event retention, access control and aggregation policy must be decided before production. Separate retained raw evidence from translated incident state.

**Validation layering:** the JSON Schema validates types, lengths and required shape. It intentionally permits **unknown future numeric status/stage/HTTPS codes** within reserved unsigned ranges so older receivers can store them safely. An additional semantic validator, driven by the registry plus this specification, checks codes, bit-mask invariants, sample age, kind-specific eligibility and freshness. Unknown values MUST NOT silently become known codes or trigger alerts.

## 11. Conformance and release gate (experimental implementation, incomplete field acceptance)

Firmware and backend refactor MUST supply test fixtures for all registries, not just successful `s=1`:
- Serializer + parser roundtrip, UTF-8, 1 KiB limit, missing vs measured-zero, malformed/unknown codes and version handling.
- Exact HMAC test vectors shared across ESP32 and backend; altered method, path, header uptime, device ID or body MUST fail.
- Duplicate identical event vs altered same `id,b,q`; ACK mismatch; 429/5xx/timeout then deduplicated retry; queue overflow accounting; reboot/boot-id change.
- 32-bit `millis()` wrap to extended monotonic `u`, valid unpredictable boot identifier, q wrap, NTP absent, TLS CA/hostname failure, clock uncertainty, replay of recorded boot events.
- `SERVICE_ACCEPT_PASS`, timeout before banner, timeout after KEXINIT, NEWKEYS observation without processed transport, `HOST_KEY_MISMATCH`, `SERVICE_ACCEPT_TIMEOUT`, local `WORKER_STALLED`.
- HTTP sample PASS, SLOW, CLOCK_NOT_READY, DNS/TLS/HTTP/body failures; no duplicate cached `h`; independent per-channel expiry.
- A simulated carrier-data-off event MUST NOT be described as ISP filtering; missing delivery MUST become device/telemetry stale, not SSH fail.
- DB transaction, idempotency, out-of-order and cross-boot ordering, historical backfill vs latest state, old sample never triggers late alert.
- Hardware: successful full build/flash with the DPT refactor, bounded RAM/stack/TLS, watchdog, Wi-Fi recovery; test comparison against observed healthy and disrupted NPV outcomes separately.
- **Only after these tests:** opt-in backend alert job with documented policy, thresholds and separate rollback.

### Explicit non-goals for DPT/1

No SIM800L, LTE modem, SMS, NPV/SSH account login, UDPGW 7300, VPN traffic, raw packet capture, censorship classifier, remote commands, OTA, service auto-restart, automatic baseline training, or production notification job. The protocol is designed to **support** these later as separate, explicitly approved work if evidence requires them.

## 12. Refactor sequence (for later approval/execution)

1. **Freeze DPT/1 + conformance fixtures** (this documentation milestone).
2. Add stable mapping functions/serializer, boot ID and monotonic event ID, observation-bit construction, bounded telemetry queue, signed HTTPS sender in ESP32; preserve existing SSH and public-HTTPS probes, no credential-based SSH.
3. Audit NVLBot implementation, choose models/migrations, implement API verification, transactionally idempotent ingestion, translation registry and read-only recent history view.
4. End-to-end replay and field tests with real hardware; compare direct-SSH observations to NPV reference audit. Validate silent/failed sender behavior.
5. Only in a **separate** approved phase, introduce incident evaluation jobs and Telegram notifications. No premature merge to `master`.

### Traceability to present firmware

As of drafting, `src/ssh_feasibility_main.cpp` defines `Code`, `StageTrace`, `stopStage()` and 30s/12-sample quality statistics; `src/https_quality.h` defines HTTP/TLS/body result statuses and 180s independent 64KiB checks. These are **source states, not wire-compatible DPT implementations**. Some local faults such as stalled worker have no existing result queue sample; they require explicit event serialization during the refactor. The device’s current LED and 12-sample rolling window are **not transmitted** as ground truth. Field observations to date support healthy SSH/HTTPS behavior; controlled failure-path/LED validation and full audit reproduction remain open.

*Original contract authoring branch: `feature/1b-ssh-feasibility-20261029`. The experimental R2-A/R2-B implementations and R2-C hardening branches now exist, but neither automatic alerts nor master merges are implied. See [R2-C hardening](014-R2C-HARDENING-FIFO-LIVE-STATE-2026-10-31.md).*
