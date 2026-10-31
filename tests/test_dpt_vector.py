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
