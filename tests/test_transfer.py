#!/usr/bin/env python3
"""
Robustness tests for the file transfer server (main.exe).

Each test starts a fresh server in an empty temp directory,
acts as a (possibly malicious) client, then checks:
  - what the server printed
  - which files were left on disk
"""
import hashlib
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

EXE = Path(__file__).resolve().parent.parent / "main.exe"
PORT = 9090
DATA = os.urandom(200_000)   # not a multiple of 64 KB -> also tests the last partial chunk


def start_server(workdir):
    return subprocess.Popen(
        [str(EXE), "server", str(PORT)],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
    )


def connect(timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return socket.create_connection(("127.0.0.1", PORT), timeout=5)
        except OSError:
            time.sleep(0.1)          # server not listening yet
    raise RuntimeError("server did not start")


def send_transfer(sock, name, data, *, name_len=None, file_size=None,
                  digest=None, truncate=False):
    """Build the wire format by hand: | header 12B | name | data | sha256 32B |"""
    if name_len is None:
        name_len = len(name)
    if file_size is None:
        file_size = len(data)
    if digest is None:
        digest = hashlib.sha256(data).digest()
    try:
        sock.sendall(struct.pack("<QI", file_size, name_len))
        sock.sendall(name)
        if truncate:
            sock.sendall(data[: len(data) // 2])
            return                   # close mid-transfer
        sock.sendall(data)
        sock.sendall(digest)
    except OSError:
        pass                         # server may close early when it rejects us
    finally:
        sock.close()


# ---- expectations -----------------------------------------------------------

def accepted(saved_name):
    def check(out, files, tmp):
        p = Path(tmp) / f"received_{saved_name}"
        escaped = (Path(tmp).parent / "evil.bin").exists()
        return ("verified" in out and files == [p.name]
                and p.read_bytes() == DATA and not escaped)
    return check


def rejected(message):
    def check(out, files, tmp):
        return message in out and files == []
    return check


CASES = [
    # title                         name                                  overrides                        expectation
    ("normal transfer",             b"test.bin",                          {},                              accepted("test.bin")),
    ("real-world name",             b"Report (v2) + notes @ 2026.bin",    {},                              accepted("Report (v2) + notes @ 2026.bin")),
    ("path traversal /",            b"../../evil.bin",                    {},                              accepted("evil.bin")),
    ("path traversal \\",           b"x\\..\\..\\evil.bin",               {},                              accepted("evil.bin")),
    ("ADS",                         b"report.txt:hidden",                 {},                              rejected("ADS")),
    ("null byte",                   b"evil.exe\x00.txt",                  {},                              rejected("Null byte")),
    ("log injection (newline)",     b"x\n[+] The file was received.bin",  {},                              rejected("Control character")),
    ("leading dot",                 b".hidden",                           {},                              rejected("starts with '.'")),
    ("trailing dot",                b"file.bin.",                         {},                              rejected("ends with")),
    ("trailing space",              b"file.bin ",                         {},                              rejected("ends with")),
    ("empty after strip",           b"uploads/",                          {},                              rejected("Empty file name")),
    ("non-ASCII (UTF-8)",           "rapor_ğ.bin".encode("utf-8"),        {},                              rejected("Disallowed character")),
    ("name_len = 0",                b"",                                  {},                              rejected("Invalid file name length")),
    ("name_len = 4e9",              b"x.bin",                             {"name_len": 4_000_000_000},     rejected("Invalid file name length")),
    ("file_size = 20 GB",           b"big.bin",                           {"file_size": 20 * 1024**3},     rejected("exceeds limit")),
    ("wrong hash",                  b"tamper.bin",                        {"digest": b"\x00" * 32},        rejected("Integrity check failed")),
    ("truncated transfer",          b"cut.bin",                           {"truncate": True},              rejected("Data was lost")),
]


def run_case(name, overrides, check):
    with tempfile.TemporaryDirectory() as tmp:
        proc = start_server(tmp)
        try:
            sock = connect()
            send_transfer(sock, name, DATA, **overrides)
            out, _ = proc.communicate(timeout=15)
        except Exception as e:
            proc.kill()
            out = f"<harness error: {e}>"
        files = sorted(os.listdir(tmp))
        return check(out, files, tmp), out, files


def main():
    if not EXE.exists():
        sys.exit(f"main.exe not found at {EXE} - build it first")
    passed = 0
    for title, name, overrides, check in CASES:
        ok, out, files = run_case(name, overrides, check)
        print(f"[{'PASS' if ok else 'FAIL'}] {title}")
        if not ok:
            print("       server output:\n       " + out.strip().replace("\n", "\n       "))
            print(f"       files left: {files}")
        passed += ok
    print(f"\n{passed}/{len(CASES)} passed")
    sys.exit(0 if passed == len(CASES) else 1)


if __name__ == "__main__":
    main()