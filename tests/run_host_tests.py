"""Compile real R1 modules against deterministic peripherals; no ESP32/network."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="denaprobe-r1-") as build:
    executable = Path(build) / "r1-tests"
    subprocess.run([
        os.environ.get("CXX", "g++"), "-std=c++17", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-format", "-DDENAPROBE_HOST_TEST", "-I", str(root / "tests/stubs"),
        str(root / "tests/test_r1.cpp"), "-o", str(executable),
    ], check=True)
    # A regression that hangs must fail CI rather than run indefinitely.
    subprocess.run([str(executable)], check=True, timeout=20)
