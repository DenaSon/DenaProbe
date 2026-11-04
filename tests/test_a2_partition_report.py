"""Synthetic parser-only tests. Never use a customer's full flash in CI."""
import struct
import tempfile
from pathlib import Path
from subprocess import run
import sys

from ops.a2_partition_report import parse_partitions, PARTITION

def fixture(slot_size: int) -> bytes:
    flash = bytearray(b"\xff" * (0x9000 + 64))
    records = [
        (0x50AA, 1, 2, 0x9000, 0x5000, b"nvs", 0),
        (0x50AA, 0, 0x10, 0x10000, slot_size, b"app0", 0),
        (0x50AA, 0, 0x11, 0x1F0000, slot_size, b"app1", 0),
    ]
    for i, (magic, typ, sub, ofs, sz, label, flags) in enumerate(records):
        PARTITION.pack_into(flash, 0x8000 + i * 32,
                            magic, typ, sub, ofs, sz, label.ljust(16, b"\x00"), flags)
    return bytes(flash)

partitions = parse_partitions(fixture(0x1E0000))
assert [p["label"] for p in partitions] == ["nvs", "app0", "app1"]
assert [p["size"] for p in partitions if p["type"] == 0] == [0x1E0000] * 2
try:
    parse_partitions(bytes(0x9000))
except ValueError:
    pass
else:
    raise AssertionError("invalid table should fail closed")
with tempfile.TemporaryDirectory() as tmp:
    image = Path(tmp) / "board.bin"
    image.write_bytes(fixture(0x140000))
    command = [sys.executable, "ops/a2_partition_report.py", str(image)]
    result = run(command, check=True, capture_output=True, text=True)
    assert "CURRENT_MAX_APP_BYTES=1310720" in result.stdout
    assert "A2_GATE=HOLD_VERIFY_NON_4MB_FLASH" in result.stdout
print("PASS A2 partition report synthetic tests")
