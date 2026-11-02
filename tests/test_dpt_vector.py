"""DPT/1 public conformance vector; never use the fixture key in a device."""
import base64
import hashlib
import hmac
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
fixtures = root / "contracts" / "dpt" / "v1"
v = json.loads((fixtures / "hmac-test-vectors.json").read_text())
raw = v["raw_body"].encode("utf-8")
sha = hashlib.sha256(raw).hexdigest()
assert sha == v["body_sha256_hex"]
body = json.loads(raw)
headers = v["headers"]
assert body["id"] == headers["X-DPT-Device"]
signed = "\n".join([
    "DPT1", "POST", "/api/dpt/v1/telemetry",
    headers["X-DPT-Device"], headers["X-DPT-Key-Id"],
    headers["X-DPT-Sent-Uptime-Ms"], sha,
])
assert signed == v["string_to_sign"]
assert int(headers["X-DPT-Sent-Uptime-Ms"]) >= body["u"]
mac = hmac.new(bytes.fromhex(v["key_hex"]), signed.encode(), hashlib.sha256).digest()
signature = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
assert signature == v["expected_signature_base64url"]
assert body == json.loads((fixtures / "fixtures.json").read_text())["valid"][1]
print("PASS DPT/1 HMAC-SHA256 public golden vector and canonical signing input")

# DPT/2 draft is a separate HMAC domain, endpoint, key ID, and ACK version.
v2 = json.loads((root / "contracts" / "dpt" / "v2" / "hmac-test-vectors.json").read_text())
raw_v2 = v2["body_utf8_exact"].encode("utf-8")
hash_v2 = hashlib.sha256(raw_v2).hexdigest()
assert hash_v2 == v2["body_sha256_lowercase_hex"]
header_v2 = v2["headers"]
assert header_v2["X-DPT-Key-Id"] == "k-test"  # synthetic public vector ONLY
assert json.loads(raw_v2)["v"] == 2
canonical_v2 = "\n".join([
    "DPT2", "POST", "/api/dpt/v2/telemetry",
    header_v2["X-DPT-Device"], header_v2["X-DPT-Key-Id"],
    header_v2["X-DPT-Sent-Uptime-Ms"], hash_v2,
])
assert canonical_v2 == v2["canonical_ascii"]
signature_v2 = base64.urlsafe_b64encode(
    hmac.new(bytes.fromhex(v2["secret_hex"]), canonical_v2.encode("ascii"),
             hashlib.sha256).digest()).rstrip(b"=").decode("ascii")
assert signature_v2 == v2["expected_signature_base64url_nopad"]
assert signature_v2 == header_v2["X-DPT-Signature"]
print("PASS DPT/2 independent HMAC-SHA256 draft golden vector")
