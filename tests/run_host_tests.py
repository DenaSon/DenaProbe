"""Compile real R1 modules against deterministic peripherals; no ESP32/network."""
import os
import sys
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
    deep_executable = Path(build) / "a1-password-tests"
    subprocess.run([
        os.environ.get("CXX", "g++"), "-std=c++17", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-format", "-DDENAPROBE_HOST_TEST", "-I", str(root / "tests/stubs"),
        str(root / "tests/test_a1_password.cpp"), "-o", str(deep_executable),
    ], check=True)
    subprocess.run([str(deep_executable)], check=True, timeout=20)
    auth_only_executable = Path(build) / "a2-auth-only-tests"
    subprocess.run([
        os.environ.get("CXX", "g++"), "-std=c++17", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-format", "-DDENAPROBE_HOST_TEST", "-I", str(root / "tests/stubs"),
        str(root / "tests/test_a2_auth_only.cpp"), "-o", str(auth_only_executable),
    ], check=True)
    subprocess.run([str(auth_only_executable)], check=True, timeout=20)
    forwarding_executable = Path(build) / "b1-forwarding-tests"
    subprocess.run([
        os.environ.get("CXX", "g++"), "-std=c++17", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-format", "-DDENAPROBE_HOST_TEST", "-I", str(root / "tests/stubs"),
        str(root / "tests/test_b1_forwarding.cpp"), "-o", str(forwarding_executable),
    ], check=True)
    subprocess.run([str(forwarding_executable)], check=True, timeout=20)
    b2_executable = Path(build) / "b2-loopback-telemetry-tests"
    subprocess.run([
        os.environ.get("CXX", "g++"), "-std=c++17", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-format", "-DDENAPROBE_HOST_TEST", "-I", str(root / "tests/stubs"),
        str(root / "tests/test_b2_loopback_telemetry.cpp"), "-o", str(b2_executable),
    ], check=True)
    subprocess.run([str(b2_executable)], check=True, timeout=20)
    # B3 compatibility mode and reserved signed auth wire use the real modules.
    for wire in (0, 1):
        edge_executable = Path(build) / f"b3-edge-auth-{wire}"
        subprocess.run([
            os.environ.get("CXX", "g++"), "-std=c++17", "-O1", "-Wall", "-Wextra",
            "-Werror", "-Wno-format", "-DDENAPROBE_HOST_TEST",
            f"-DPROBE_B3_AUTH_WIRE={wire}", "-I", str(root / "tests/stubs"),
            str(root / "tests/test_b3_edge_auth.cpp"), "-o", str(edge_executable),
        ], check=True)
        subprocess.run([str(edge_executable)], check=True, timeout=20)
    for wire in (0, 1):
        lite_executable = Path(build) / f"lite-transfer-{wire}"
        subprocess.run([
            os.environ.get("CXX", "g++"), "-std=c++17", "-O1", "-Wall", "-Wextra",
            "-Werror", "-Wno-format", "-DDENAPROBE_HOST_TEST",
            f"-DPROBE_B3_LITE_WIRE={wire}", f"-DPROBE_B3_AUTH_WIRE={wire}",
            f"-DPROBE_DPT_PROTOCOL_VERSION={2 if wire else 1}",
            "-I", str(root / "tests/stubs"),
            str(root / "tests/test_lite.cpp"), "-o", str(lite_executable),
        ], check=True)
        subprocess.run([str(lite_executable)], check=True, timeout=20)
    invalid_executable = Path(build) / "lite-invalid-target"
    subprocess.run([
        os.environ.get("CXX", "g++"), "-std=c++17", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-format", "-DDENAPROBE_HOST_TEST",
        "-I", str(root / "tests/stubs"),
        str(root / "tests/test_lite_invalid_target.cpp"),
        "-o", str(invalid_executable),
    ], check=True)
    subprocess.run([str(invalid_executable)], check=True, timeout=20)
    subprocess.run([sys.executable, str(root / "tests/test_a2_partition_report.py")], check=True, timeout=10)
    subprocess.run([sys.executable, str(root / "tests/test_dpt_vector.py")], check=True, timeout=10)
