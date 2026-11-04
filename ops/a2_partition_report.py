#!/usr/bin/env python3
"""Read only ESP32 app/partition metadata from a locally saved full-flash image.

This tool does not access the ESP32 and NEVER uploads, copies or prints bytes
from any non-partition area. The input flash image may contain credentials:
keep it private under the gitignored .pio directory.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import struct
import sys

PARTITION_TABLE_OFFSET = 0x8000
PARTITION_TABLE_END = 0x9000
PARTITION = struct.Struct("<HBBII16sI")
MAGIC = 0x50AA
A2_IMAGE_BYTES = 1_429_856  # CI reference only; confirm the local build size.


def parse_partitions(flash: bytes) -> list[dict]:
    if len(flash) < PARTITION_TABLE_END:
        raise ValueError("Flash image too short to contain partition table")
    out = []
    for pos in range(PARTITION_TABLE_OFFSET, PARTITION_TABLE_END, PARTITION.size):
        magic, part_type, subtype, offset, size, raw_label, flags = PARTITION.unpack_from(flash, pos)
        if magic == 0xFFFF:
            break
        if magic != MAGIC:
            # MD5 checksum entries use a different magic and are not partitions.
            continue
        label = raw_label.split(b"\x00", 1)[0].decode("ascii", "replace")
        out.append(dict(label=label, type=part_type, subtype=subtype,
                        offset=offset, size=size, flags=flags))
    if not out:
        raise ValueError("No valid partition records at 0x8000; possible encrypted or non-standard flash image")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("flash", type=Path, help="Local full-flash backup, never share the image")
    args = parser.parse_args()
    raw = args.flash.read_bytes()
    entries = parse_partitions(raw)
    print("A2_FLASH_BYTES=" + str(len(raw)))
    print("PARTITION_TABLE_OFFSET=0x8000")
    for e in entries:
        kind = "app" if e["type"] == 0 else "data" if e["type"] == 1 else "other"
        print(f"PARTITION label={e['label']} type={kind} subtype=0x{e['subtype']:02X} "
              f"offset=0x{e['offset']:X} bytes={e['size']}")
    app = [e["size"] for e in entries if e["type"] == 0]
    if not app:
        print("A2_GATE=HOLD_NO_APP_SLOT")
        return 2
    max_app = max(app)
    print(f"CURRENT_MAX_APP_BYTES={max_app}")
    print(f"A2_CI_REFERENCE_BYTES={A2_IMAGE_BYTES}")
    if len(raw) != 4 * 1024 * 1024:
        print("A2_GATE=HOLD_VERIFY_NON_4MB_FLASH")
    elif max_app < A2_IMAGE_BYTES:
        print("A2_GATE=HOLD_REPARTITION_REVIEW_REQUIRED")
    else:
        print("A2_GATE=CAPACITY_ONLY_CHECK_PASSED_OTHER_GATES_OPEN")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, struct.error) as exc:
        print(f"A2_GATE=HOLD_READ_ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
