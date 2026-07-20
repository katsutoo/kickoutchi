#!/usr/bin/env python3
import hashlib
import os
import platform
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NoReturn, cast

SAMPLES_MAX = 100_000
WARMUPS_MAX = 10_000
CHILD_TIMEOUT_SECONDS = 30
ARTIFACT_BYTES_MAX = 256 * 1024 * 1024
SOURCE_PATHS = ("Cargo.toml", "Cargo.lock", "build.rs", "src", "tests")


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def positive_integer(value: str, name: str, maximum: int, *, zero_allowed: bool) -> int:
    try:
        parsed = int(value)
    except ValueError:
        fail(f"{name} must be an integer")
    minimum = 0 if zero_allowed else 1
    if parsed < minimum or parsed > maximum:
        fail(f"{name} must be in {minimum}..={maximum}")
    return parsed


def run_git(*arguments: str, binary: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", *arguments],
        check=True,
        capture_output=True,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    return result.stdout if binary else result.stdout.decode().strip()


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


if len(sys.argv) not in range(2, 6):
    fail("usage: collect-list-samples.py BINARY [SAMPLES] [WARMUPS] [OUTPUT]")

binary = Path(sys.argv[1]).resolve()
samples = positive_integer(sys.argv[2] if len(sys.argv) > 2 else "200", "samples", SAMPLES_MAX, zero_allowed=False)
warmups = positive_integer(sys.argv[3] if len(sys.argv) > 3 else "8", "warmups", WARMUPS_MAX, zero_allowed=True)
output = Path(sys.argv[4] if len(sys.argv) > 4 else "/tmp/kickoutchi-list-latency.tsv").resolve()

product_status = cast(
    str,
    run_git("status", "--porcelain=v1", "--untracked-files=all", "--", *SOURCE_PATHS),
)
untracked_product_files = [
    line[3:] for line in product_status.splitlines() if line.startswith("?? ")
]
if untracked_product_files:
    fail(
        "benchmark source contains untracked product files: "
        + ", ".join(untracked_product_files)
    )

artifact_directory = tempfile.TemporaryDirectory(prefix="kickoutchi-benchmark-")
artifact_snapshot, artifact_sha256 = snapshot_executable(
    binary, Path(artifact_directory.name)
)
command = [str(artifact_snapshot), "list", "--json"]
for _ in range(warmups):
    try:
        subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=CHILD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"benchmark warmup failed: {error}")

source_commit = run_git("rev-parse", "HEAD")
source_dirty = bool(run_git("status", "--porcelain=v1"))
source_patch = cast(
    bytes,
    run_git("diff", "--binary", "HEAD", "--", *SOURCE_PATHS, binary=True),
)
output.parent.mkdir(parents=True, exist_ok=True)
failures = 0
temporary_path: Path | None = None
try:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output.parent,
        prefix=f".{output.name}.",
        delete=False,
    ) as file:
        temporary_path = Path(file.name)
        file.write(f"# source_commit={source_commit}\n")
        file.write(f"# source_dirty={str(source_dirty).lower()}\n")
        file.write(f"# source_patch_sha256={hashlib.sha256(source_patch).hexdigest()}\n")
        file.write(f"# artifact_sha256={artifact_sha256}\n")
        file.write(f"# python={platform.python_version()}\n")
        file.write(f"# kernel={platform.system()} {platform.release()} {platform.machine()}\n")
        file.write(f"# warmups={warmups}\n")
        file.write(f"# samples={samples}\n")
        file.write(f"# child_timeout_seconds={CHILD_TIMEOUT_SECONDS}\n")
        file.write("sample\tlatency_ns\tstatus\n")

        for sample in range(1, samples + 1):
            started_ns = time.monotonic_ns()
            try:
                result = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=CHILD_TIMEOUT_SECONDS,
                )
                status = result.returncode if 0 <= result.returncode <= 255 else 255
            except subprocess.TimeoutExpired:
                status = 124
            except OSError:
                status = 255
            completed_ns = time.monotonic_ns()
            failures += int(status != 0)
            file.write(f"{sample}\t{completed_ns - started_ns}\t{status}\n")

        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary_path, output)
    temporary_path = None
finally:
    if temporary_path is not None:
        temporary_path.unlink(missing_ok=True)

print(f"wrote {samples} samples with {failures} failures to {output}")
raise SystemExit(int(failures != 0))
