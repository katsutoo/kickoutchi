#!/usr/bin/env python3
import hashlib
import json
import os
import platform
import resource
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NoReturn, cast

SAMPLES_MAX = 1_000
WARMUPS_MAX = 100
CHILD_TIMEOUT_SECONDS = 10
ARTIFACT_BYTES_MAX = 256 * 1024 * 1024
SOURCE_BYTES_MAX = 64 * 1024 * 1024
SOURCE_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "src",
    "tests",
    "benchmarks/collect-watch-samples.py",
    "benchmarks/measure-linux-peak-rss.py",
    "benchmarks/summarize-list-samples.py",
)
BUILD_COMMAND = "cargo build --locked --profile dist --all-features --bin kickoutchi --bin kick"


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def bounded_integer(value: str, name: str, maximum: int, minimum: int) -> int:
    try:
        parsed = int(value)
    except ValueError:
        fail(f"{name} must be an integer")
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


def command_version(command: str) -> str:
    try:
        result = subprocess.run(
            [command, "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=CHILD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return result.stdout.strip()


def physical_memory_bytes() -> int | None:
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (OSError, ValueError):
        return None


def untracked_patch(relative: str) -> bytes:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--binary",
            "--unified=0",
            "--no-index",
            "--",
            "/dev/null",
            relative,
        ],
        check=False,
        capture_output=True,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    if result.returncode != 1:
        fail(f"could not capture untracked benchmark source {relative}")
    return result.stdout


def source_fingerprint() -> tuple[str, bool, bytes, str]:
    commit = cast(str, run_git("rev-parse", "HEAD"))
    status = cast(
        str,
        run_git("status", "--porcelain=v1", "--untracked-files=all", "--", *SOURCE_PATHS),
    )
    tracked_patch = cast(
        bytes,
        run_git(
            "diff", "--binary", "--unified=0", "HEAD", "--", *SOURCE_PATHS, binary=True
        ),
    )
    patches = [tracked_patch]
    retained = len(tracked_patch)
    if retained > SOURCE_BYTES_MAX:
        fail(f"benchmark source fingerprint exceeds {SOURCE_BYTES_MAX} bytes")
    untracked = sorted(line[3:] for line in status.splitlines() if line.startswith("?? "))
    for relative in untracked:
        path = Path(relative)
        try:
            metadata = path.stat()
        except OSError as error:
            fail(f"could not inspect untracked benchmark source {relative}: {error}")
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            fail(f"untracked benchmark source is not a regular file: {relative}")
        patch = untracked_patch(relative)
        retained += len(patch)
        if retained > SOURCE_BYTES_MAX:
            fail(f"benchmark source fingerprint exceeds {SOURCE_BYTES_MAX} bytes")
        patches.append(patch)
    source_patch = b"".join(patches)
    return commit, bool(status), source_patch, hashlib.sha256(source_patch).hexdigest()


def require_absent(*paths: Path) -> None:
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            fail(f"could not inspect evidence path {path}: {error}")
        fail(f"evidence path already exists: {path}")


def write_bytes(path: Path, contents: bytes) -> None:
    with path.open("xb") as file:
        file.write(contents)
        file.flush()
        os.fsync(file.fileno())


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
        with os.fdopen(os.dup(descriptor), "rb") as source, snapshot.open("xb") as target:
            copied = 0
            while chunk := source.read(1024 * 1024):
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


if len(sys.argv) not in range(2, 7):
    fail(
        "usage: collect-watch-samples.py BINARY [SAMPLES [WARMUPS "
        "[WORKLOAD [OUTPUT]]]]; WORKLOAD must be watch or why"
    )

binary = Path(sys.argv[1]).resolve()
samples = bounded_integer(sys.argv[2] if len(sys.argv) > 2 else "30", "samples", SAMPLES_MAX, 1)
warmups = bounded_integer(sys.argv[3] if len(sys.argv) > 3 else "2", "warmups", WARMUPS_MAX, 0)
workload = "watch"
if len(sys.argv) > 4:
    workload = sys.argv[4]
    if workload not in {"watch", "why"}:
        fail("workload must be watch or why")
default_output = f"/tmp/kickoutchi-{workload}-latency.tsv"
output = Path(sys.argv[5] if len(sys.argv) > 5 else default_output).resolve()
source_patch_path = Path(f"{output}.source.patch")
output.parent.mkdir(parents=True, exist_ok=True)
require_absent(output, source_patch_path)
evidence_directory = tempfile.TemporaryDirectory(
    prefix=f".{output.name}.", dir=output.parent
)
temporary_output = Path(evidence_directory.name) / "samples.tsv"
temporary_source_patch = Path(evidence_directory.name) / "source.patch"
artifact_directory = tempfile.TemporaryDirectory(prefix="kickoutchi-watch-benchmark-")
artifact, artifact_sha256 = snapshot_executable(binary, Path(artifact_directory.name))
source_commit, source_dirty, source_patch, source_patch_sha256 = source_fingerprint()
rustc_version = command_version("rustc")
config_home = Path(artifact_directory.name) / "config"
config_home.mkdir()
benchmark_environment = os.environ.copy()
benchmark_environment["XDG_CONFIG_HOME"] = str(config_home)
if workload == "watch":
    command = [
        str(artifact),
        "watch",
        "--address",
        "192.0.2.1",
        "--interval",
        "100ms",
        "--duration",
        "500ms",
        "--json",
    ]
    successful_statuses = {0}
else:
    command = [
        str(artifact),
        "why",
        "49152",
        "--all-protocols",
        "--all-addresses",
        "--json",
    ]
    successful_statuses = {0, 3}

for _ in range(warmups):
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=benchmark_environment,
        check=False,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    if result.returncode not in successful_statuses:
        fail(f"benchmark warmup failed with status {result.returncode}")

if workload == "why":
    validation = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=benchmark_environment,
        check=False,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    if validation.returncode not in successful_statuses:
        fail(f"benchmark validation failed with status {validation.returncode}")
    try:
        document = json.loads(validation.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"benchmark validation did not emit valid JSON: {error}")
    if len(document.get("results", [])) != 8:
        fail("benchmark validation did not evaluate eight endpoints")
    if document.get("aggregate_exit_code") != validation.returncode:
        fail("benchmark aggregate exit does not match process status")

usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
failures = 0
with temporary_output.open(
    mode="w",
    encoding="utf-8",
) as file:
    file.write(f"# artifact_sha256={artifact_sha256}\n")
    file.write(f"# artifact_bytes={artifact.stat().st_size}\n")
    file.write(f"# source_commit={source_commit}\n")
    file.write(f"# source_dirty={str(source_dirty).lower()}\n")
    file.write(f"# source_patch_sha256={source_patch_sha256}\n")
    file.write(f"# source_patch_file={source_patch_path.name}\n")
    file.write(f"# build_command={BUILD_COMMAND}\n")
    file.write(f"# python={platform.python_version()}\n")
    file.write(f"# rustc={rustc_version}\n")
    file.write(f"# kernel={platform.system()} {platform.release()} {platform.machine()}\n")
    file.write(f"# cpu={platform.processor() or 'unavailable'}\n")
    file.write(f"# cpu_count={os.cpu_count()}\n")
    file.write(f"# physical_memory_bytes={physical_memory_bytes() or 'unavailable'}\n")
    try:
        load_average = ",".join(f"{value:.2f}" for value in os.getloadavg())
    except (AttributeError, OSError):
        load_average = "unavailable"
    file.write(f"# load_average={load_average}\n")
    file.write("# config=isolated_empty\n")
    file.write(f"# command={' '.join(command[1:])}\n")
    file.write(f"# workload={workload}\n")
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
                env=benchmark_environment,
                check=False,
                timeout=CHILD_TIMEOUT_SECONDS,
            )
            status = result.returncode if 0 <= result.returncode <= 255 else 255
        except subprocess.TimeoutExpired:
            status = 124
        except OSError:
            status = 255
        completed_ns = time.monotonic_ns()
        failures += int(status not in successful_statuses)
        file.write(f"{sample}\t{completed_ns - started_ns}\t{status}\n")
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    file.write(f"# failures={failures}\n")
    file.write(f"# user_cpu_seconds={usage_after.ru_utime - usage_before.ru_utime:.6f}\n")
    file.write(f"# system_cpu_seconds={usage_after.ru_stime - usage_before.ru_stime:.6f}\n")
    file.flush()
    os.fsync(file.fileno())

final_commit, final_dirty, final_patch, final_patch_sha256 = source_fingerprint()
if (final_commit, final_dirty, final_patch_sha256) != (
    source_commit,
    source_dirty,
    source_patch_sha256,
):
    fail("benchmark source changed while samples were collected")
if final_patch != source_patch:
    fail("benchmark source patch changed without changing its fingerprint")

write_bytes(temporary_source_patch, source_patch)
publish_new(temporary_source_patch, source_patch_path)
publish_new(temporary_output, output)

print(
    f"wrote {samples} {workload} samples with {failures} failures to {output} "
    f"and source patch to {source_patch_path}"
)
raise SystemExit(int(failures != 0))
