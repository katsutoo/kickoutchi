#!/usr/bin/env python3
import hashlib
import os
import resource
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

SAMPLES_MAX = 10_000
CHILD_TIMEOUT_SECONDS = 30
ARTIFACT_BYTES_MAX = 256 * 1024 * 1024


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def snapshot_executable(path: Path, directory: Path) -> tuple[Path, str]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"could not open benchmark binary: {error}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1:
            fail(f"benchmark binary is not a nonempty regular file: {path}")
        if metadata.st_size > ARTIFACT_BYTES_MAX:
            fail(f"benchmark binary exceeds {ARTIFACT_BYTES_MAX} bytes")
        if metadata.st_mode & 0o111 == 0:
            fail(f"benchmark binary has no executable mode bit: {path}")

        snapshot = directory / "benchmark-artifact"
        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(os.dup(descriptor), "rb") as source, snapshot.open("xb") as target:
            while chunk := source.read(min(1024 * 1024, ARTIFACT_BYTES_MAX + 1 - copied)):
                copied += len(chunk)
                if copied > ARTIFACT_BYTES_MAX:
                    fail(f"benchmark binary exceeds {ARTIFACT_BYTES_MAX} bytes")
                digest.update(chunk)
                target.write(chunk)
        if copied != metadata.st_size:
            fail("benchmark binary changed while its private snapshot was created")
        snapshot.chmod(0o700)
        return snapshot, digest.hexdigest()
    finally:
        os.close(descriptor)


if len(sys.argv) > 3:
    fail("usage: measure-linux-peak-rss.py [BINARY] [SAMPLES]")

binary = Path(sys.argv[1] if len(sys.argv) > 1 else "target/dist/kick").resolve()
try:
    samples = int(sys.argv[2]) if len(sys.argv) > 2 else 20
except ValueError:
    fail("samples must be a positive integer")

if samples < 1 or samples > SAMPLES_MAX:
    fail(f"samples must be in 1..={SAMPLES_MAX}")

artifact_directory = tempfile.TemporaryDirectory(prefix="kickoutchi-benchmark-")
artifact_snapshot, artifact_sha256 = snapshot_executable(
    binary, Path(artifact_directory.name)
)
failures = 0
for _ in range(samples):
    try:
        result = subprocess.run(
            [str(artifact_snapshot), "list", "--json"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=CHILD_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        failures += 1
        continue
    except OSError as error:
        fail(f"could not execute benchmark binary: {error}")
    failures += int(result.returncode != 0)

# On Linux ru_maxrss is the maximum resident set size in KiB across waited-for
# children. subprocess.run waits for every measured child before returning.
peak_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
print(
    f"artifact_sha256={artifact_sha256} samples={samples} "
    f"failures={failures} peak_rss_kib={peak_kib}"
)
raise SystemExit(int(failures != 0))
