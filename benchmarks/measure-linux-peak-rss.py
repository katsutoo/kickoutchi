#!/usr/bin/env python3
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NoReturn

SAMPLES_MAX = 10_000
CHILD_TIMEOUT_SECONDS = 30
ARTIFACT_BYTES_MAX = 256 * 1024 * 1024


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def require_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        fail(f"could not inspect evidence path {path}: {error}")
    fail(f"evidence path already exists: {path}")


def publish_new(temporary_path: Path, path: Path) -> None:
    try:
        os.link(temporary_path, path)
    except FileExistsError:
        fail(f"evidence path already exists: {path}")
    except OSError as error:
        fail(f"could not publish evidence path {path}: {error}")


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


def run_with_rss(command: list[str], environment: dict[str, str]) -> tuple[int, int]:
    with subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
    ) as process:
        deadline = time.monotonic() + CHILD_TIMEOUT_SECONDS
        while True:
            pid, wait_status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid != 0:
                return_code = os.waitstatus_to_exitcode(wait_status)
                process.returncode = return_code
                status = return_code if 0 <= return_code <= 255 else 255
                return status, usage.ru_maxrss
            if time.monotonic() >= deadline:
                process.kill()
                _, _, usage = os.wait4(process.pid, 0)
                process.returncode = -9
                return 124, usage.ru_maxrss
            time.sleep(0.01)


if len(sys.argv) > 5:
    fail("usage: measure-linux-peak-rss.py [BINARY] [SAMPLES] [list|watch|why] [OUTPUT]")

binary = Path(sys.argv[1] if len(sys.argv) > 1 else "target/dist/kick").resolve()
try:
    samples = int(sys.argv[2]) if len(sys.argv) > 2 else 20
except ValueError:
    fail("samples must be a positive integer")

if samples < 1 or samples > SAMPLES_MAX:
    fail(f"samples must be in 1..={SAMPLES_MAX}")
workload = sys.argv[3] if len(sys.argv) > 3 else "list"
if workload not in {"list", "watch", "why"}:
    fail("workload must be list, watch, or why")
output = Path(
    sys.argv[4] if len(sys.argv) > 4 else "/tmp/kickoutchi-peak-rss.tsv"
).resolve()
output.parent.mkdir(parents=True, exist_ok=True)
require_absent(output)
evidence_directory = tempfile.TemporaryDirectory(
    prefix=f".{output.name}.", dir=output.parent
)
temporary_output = Path(evidence_directory.name) / "samples.tsv"

artifact_directory = tempfile.TemporaryDirectory(prefix="kickoutchi-benchmark-")
artifact_snapshot, artifact_sha256 = snapshot_executable(
    binary, Path(artifact_directory.name)
)
config_home = Path(artifact_directory.name) / "config"
config_home.mkdir()
environment = os.environ.copy()
environment["XDG_CONFIG_HOME"] = str(config_home)
command: list[str]
if workload == "list":
    command = [str(artifact_snapshot), "list", "--json"]
elif workload == "watch":
    command = [
        str(artifact_snapshot),
        "watch",
        "--address",
        "192.0.2.1",
        "--interval",
        "100ms",
        "--duration",
        "500ms",
        "--json",
    ]
else:
    command = [
        str(artifact_snapshot),
        "why",
        "49152",
        "--all-protocols",
        "--all-addresses",
        "--json",
    ]
failures = 0
rows: list[tuple[int, int, int]] = []
for sample in range(1, samples + 1):
    try:
        status, peak_kib = run_with_rss(command, environment)
    except OSError as error:
        fail(f"could not execute benchmark binary: {error}")
    failures += int(status not in ({0, 3} if workload == "why" else {0}))
    rows.append((sample, status, peak_kib))

peak_kib = max(peak for _, _, peak in rows)
with temporary_output.open(
    mode="w",
    encoding="utf-8",
) as file:
    file.write(f"# artifact_sha256={artifact_sha256}\n")
    file.write(f"# artifact_bytes={artifact_snapshot.stat().st_size}\n")
    file.write(f"# workload={workload}\n")
    file.write(f"# command={' '.join(command[1:])}\n")
    file.write(f"# samples={samples}\n")
    file.write(f"# child_timeout_seconds={CHILD_TIMEOUT_SECONDS}\n")
    file.write("sample\tstatus\tpeak_rss_kib\n")
    for sample, status, sample_peak_kib in rows:
        file.write(f"{sample}\t{status}\t{sample_peak_kib}\n")
    file.write(f"# failures={failures}\n")
    file.write(f"# peak_rss_kib={peak_kib}\n")
    file.flush()
    os.fsync(file.fileno())
publish_new(temporary_output, output)
print(
    f"artifact_sha256={artifact_sha256} samples={samples} "
    f"workload={workload} failures={failures} peak_rss_kib={peak_kib} output={output}"
)
raise SystemExit(int(failures != 0))
