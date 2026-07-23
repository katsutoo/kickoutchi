#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, NoReturn

ARCHIVE_BYTES_MAX = 256 * 1024 * 1024
BINARY_BYTES_MAX = 256 * 1024 * 1024
ARCHIVE_MEMBERS_MAX = 64
ARCHIVE_EXPANDED_BYTES_MAX = 512 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 30
VERSION_OUTPUT_BYTES_MAX = 4096
TEST_TIMEOUT_SECONDS = 20 * 60
TARGET_PATTERN = re.compile(r"^[a-z0-9_]+(?:-[a-z0-9_]+)+$")


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def native_target(runner_os: str, runner_arch: str) -> str:
    targets = {
        ("Linux", "X64"): "x86_64-unknown-linux-gnu",
        ("Linux", "ARM64"): "aarch64-unknown-linux-gnu",
        ("macOS", "X64"): "x86_64-apple-darwin",
        ("macOS", "ARM64"): "aarch64-apple-darwin",
        ("Windows", "X64"): "x86_64-pc-windows-msvc",
    }
    try:
        return targets[(runner_os, runner_arch)]
    except KeyError:
        fail(f"unsupported native runner: {runner_os}/{runner_arch}")


def parse_targets(raw: str) -> list[str]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"targets must be valid JSON: {error}")
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        fail("targets must contain 1..=16 entries")
    if not all(isinstance(item, str) and TARGET_PATTERN.fullmatch(item) for item in value):
        fail("targets contain an invalid target triple")
    if len(set(value)) != len(value):
        fail("targets must be unique")
    return value


def require_single_native_target(targets: list[str], target: str) -> None:
    if targets != [target]:
        fail(
            f"matrix targets {targets} must contain only native runner target {target}; "
            "release archives require one matching native execution per job"
        )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(archive: Path, digest: str) -> None:
    checksum_path = Path(f"{archive}.sha256")
    if not checksum_path.is_file() or checksum_path.is_symlink():
        fail(f"missing regular checksum file for {archive.name}")
    if not 1 <= checksum_path.stat().st_size <= 1024:
        fail(f"checksum file size is outside the approved bound for {archive.name}")
    lines = checksum_path.read_text(encoding="ascii").splitlines()
    records = [line for line in lines if line]
    if len(records) != 1:
        fail(f"checksum file must contain exactly one record for {archive.name}")
    match = re.fullmatch(r"([0-9a-fA-F]{64})(?:  | \*)([^\s]+)", records[0])
    if match is None or match.group(2) != archive.name:
        fail(f"invalid checksum file for {archive.name}")
    if match.group(1).lower() != digest:
        fail(f"checksum mismatch for {archive.name}")


def safe_member_name(name: str, *, directory: bool = False) -> PurePosixPath:
    if directory:
        if name.endswith("//"):
            fail(f"noncanonical archive directory path: {name!r}")
        if name.endswith("/"):
            name = name[:-1]
    elif name.endswith("/"):
        fail(f"noncanonical archive file path: {name!r}")

    parts = name.split("/")
    path = PurePosixPath(*parts)
    if (
        "\\" in name
        or path.is_absolute()
        or not name
        or path.parts[0].endswith(":")
        or any(part in ("", ".", "..") for part in parts)
        or path.as_posix() != name
    ):
        fail(f"unsafe archive member path: {name!r}")
    return path


def expected_archive_paths(
    target: str, windows: bool
) -> tuple[set[PurePosixPath], set[PurePosixPath]]:
    executable_suffix = ".exe" if windows else ""
    files = {
        PurePosixPath("CHANGELOG.md"),
        PurePosixPath("LICENSE"),
        PurePosixPath("README.md"),
        PurePosixPath(f"kickoutchi{executable_suffix}"),
        PurePosixPath(f"kick{executable_suffix}"),
    }
    if windows:
        return files, set()
    root = PurePosixPath(f"kickoutchi-{target}")
    return {root / path for path in files}, {root}


def extract_tar_binaries(
    archive: Path, destination: Path, target: str, expected: set[str]
) -> dict[str, Path]:
    selected: dict[str, Path] = {}
    expected_files, expected_directories = expected_archive_paths(target, windows=False)
    seen_files: set[PurePosixPath] = set()
    seen_directories: set[PurePosixPath] = set()
    member_count = 0
    expanded_bytes = 0
    with tarfile.open(archive, mode="r|xz") as bundle:
        for member in bundle:
            member_count += 1
            if member_count > ARCHIVE_MEMBERS_MAX:
                fail("release archive member count is outside the approved bound")
            member_path = safe_member_name(member.name, directory=member.isdir())
            expanded_bytes += member.size
            if expanded_bytes > ARCHIVE_EXPANDED_BYTES_MAX:
                fail("release archive expanded size is outside the approved bound")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                fail(f"release archive contains a forbidden member: {member.name}")
            if member.isdir():
                if member_path in seen_directories:
                    fail(f"release archive contains a duplicate directory: {member.name}")
                seen_directories.add(member_path)
                continue
            if not member.isfile():
                fail(f"release archive contains an unsupported member: {member.name}")
            if member_path in seen_files:
                fail(f"release archive contains a duplicate member: {member.name}")
            seen_files.add(member_path)
            if member_path not in expected_files:
                fail(f"release archive contains an unexpected member: {member.name}")
            if member_path.name not in expected:
                continue
            if not 1 <= member.size <= BINARY_BYTES_MAX:
                fail(f"release binary size is outside the approved bound: {member_path.name}")
            if member.mode & 0o111 == 0:
                fail(f"release binary is not executable: {member_path.name}")
            source = bundle.extractfile(member)
            if source is None:
                fail(f"release binary could not be read: {member_path.name}")
            output = destination / member_path.name
            with source, output.open("xb") as target_file:
                shutil.copyfileobj(source, target_file, length=1024 * 1024)
            if output.stat().st_size != member.size:
                fail(f"release binary size changed during extraction: {member_path.name}")
            output.chmod(member.mode & 0o777)
            selected[member_path.name] = output
    if member_count < 1:
        fail("release archive member count is outside the approved bound")
    if seen_files != expected_files or seen_directories != expected_directories:
        fail("release archive layout differs from the cargo-dist contract")
    return selected


def zip_member_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return mode != 0 and stat.S_ISLNK(mode)


def zip_entry_count(archive: Path) -> int:
    with archive.open("rb") as file:
        size = file.seek(0, os.SEEK_END)
        retained = min(size, 65_557)
        file.seek(size - retained)
        suffix = file.read(retained)
    offset = suffix.rfind(b"PK\x05\x06")
    if offset < 0 or len(suffix) - offset < 22:
        fail("release ZIP has no valid end-of-central-directory record")
    disk, central_disk, disk_entries, total_entries = struct.unpack_from(
        "<HHHH", suffix, offset + 4
    )
    comment_bytes = struct.unpack_from("<H", suffix, offset + 20)[0]
    if offset + 22 + comment_bytes != len(suffix):
        fail("release ZIP end-of-central-directory record is malformed")
    if disk != 0 or central_disk != 0 or disk_entries != total_entries:
        fail("multi-disk release ZIPs are forbidden")
    if total_entries == 0xFFFF:
        fail("ZIP64 release archives are outside the approved contract")
    return total_entries


def extract_zip_binaries(
    archive: Path, destination: Path, target: str, expected: set[str]
) -> dict[str, Path]:
    entry_count = zip_entry_count(archive)
    if not 1 <= entry_count <= ARCHIVE_MEMBERS_MAX:
        fail("release archive member count is outside the approved bound")
    selected: dict[str, Path] = {}
    expected_files, expected_directories = expected_archive_paths(target, windows=True)
    seen_files: set[PurePosixPath] = set()
    seen_directories: set[PurePosixPath] = set()
    expanded_bytes = 0
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) != entry_count:
            fail("release ZIP entry count changed while opening the archive")
        for member in members:
            member_path = safe_member_name(member.filename, directory=member.is_dir())
            expanded_bytes += member.file_size
            if expanded_bytes > ARCHIVE_EXPANDED_BYTES_MAX:
                fail("release archive expanded size is outside the approved bound")
            if member.flag_bits & 0x1:
                fail(f"release archive contains an encrypted member: {member.filename}")
            if zip_member_is_symlink(member):
                fail(f"release archive contains a symbolic link: {member.filename}")
            if member.is_dir():
                if member_path in seen_directories:
                    fail(f"release archive contains a duplicate directory: {member.filename}")
                seen_directories.add(member_path)
                continue
            if member_path in seen_files:
                fail(f"release archive contains a duplicate member: {member.filename}")
            seen_files.add(member_path)
            if member_path not in expected_files:
                fail(f"release archive contains an unexpected member: {member.filename}")
            if member_path.name not in expected:
                continue
            if not 1 <= member.file_size <= BINARY_BYTES_MAX:
                fail(f"release binary size is outside the approved bound: {member_path.name}")
            output = destination / member_path.name
            with bundle.open(member) as source, output.open("xb") as target_file:
                shutil.copyfileobj(source, target_file, length=1024 * 1024)
            if output.stat().st_size != member.file_size:
                fail(f"release binary size changed during extraction: {member_path.name}")
            selected[member_path.name] = output
    if seen_files != expected_files or seen_directories != expected_directories:
        fail("release archive layout differs from the cargo-dist contract")
    return selected


def read_bounded(
    pipe: BinaryIO,
    limit: int,
    result: list[bytes | Exception],
    overflow: threading.Event,
) -> None:
    retained = bytearray()
    try:
        while chunk := pipe.read(min(4096, limit + 1 - len(retained))):
            retained.extend(chunk)
            if len(retained) > limit:
                overflow.set()
                break
        result.append(bytes(retained))
    except Exception as error:
        result.append(error)
    finally:
        pipe.close()


def run_version(binary: Path, expected_version: str) -> None:
    process = subprocess.Popen(
        [str(binary), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        fail(f"version pipes could not be created for {binary.name}")
    overflow = threading.Event()
    stdout_result: list[bytes | Exception] = []
    stderr_result: list[bytes | Exception] = []
    readers = [
        threading.Thread(
            target=read_bounded,
            args=(process.stdout, VERSION_OUTPUT_BYTES_MAX, stdout_result, overflow),
            daemon=True,
        ),
        threading.Thread(
            target=read_bounded,
            args=(process.stderr, VERSION_OUTPUT_BYTES_MAX, stderr_result, overflow),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    while process.poll() is None and not overflow.is_set() and time.monotonic() < deadline:
        time.sleep(0.01)
    timed_out = process.poll() is None and not overflow.is_set()
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)
    for reader in readers:
        reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        fail(f"version output readers did not stop for {binary.name}")
    if timed_out:
        fail(f"version command exceeded its deadline for {binary.name}")
    if overflow.is_set():
        fail(f"version output exceeded its byte limit for {binary.name}")
    if len(stdout_result) != 1 or len(stderr_result) != 1:
        fail(f"version output was not collected for {binary.name}")
    if isinstance(stdout_result[0], Exception) or isinstance(stderr_result[0], Exception):
        fail(f"version output collection failed for {binary.name}")
    try:
        stdout_text = stdout_result[0].decode("utf-8")
        stderr_text = stderr_result[0].decode("utf-8")
    except UnicodeDecodeError:
        fail(f"version output was not UTF-8 for {binary.name}")
    expected = f"kickoutchi {expected_version}\n"
    if process.returncode != 0 or stdout_text != expected or stderr_text:
        fail(f"unexpected version output from {binary.name}")


def package_version() -> str:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    metadata = json.loads(result.stdout)
    packages = [package for package in metadata["packages"] if package["name"] == "kickoutchi"]
    if len(packages) != 1 or not isinstance(packages[0].get("version"), str):
        fail("cargo metadata must contain exactly one kickoutchi package version")
    return packages[0]["version"]


def validate_release_artifact(
    distrib_path: Path, targets_json: str, runner_os: str, runner_arch: str
) -> dict[str, object]:
    targets = parse_targets(targets_json)
    target = native_target(runner_os, runner_arch)
    require_single_native_target(targets, target)

    distrib = distrib_path.resolve(strict=True)
    if not distrib.is_dir():
        fail("distribution path must be a directory")
    suffix = ".zip" if runner_os == "Windows" else ".tar.xz"
    archive = distrib / f"kickoutchi-{target}{suffix}"
    if not archive.is_file() or archive.is_symlink():
        fail(f"missing regular native release archive: {archive.name}")
    archive_size = archive.stat().st_size
    if not 1 <= archive_size <= ARCHIVE_BYTES_MAX:
        fail("release archive size is outside the approved bound")
    archive_sha256 = sha256(archive)
    verify_checksum(archive, archive_sha256)
    expected_version = package_version()

    executable_suffix = ".exe" if runner_os == "Windows" else ""
    expected = {f"kickoutchi{executable_suffix}", f"kick{executable_suffix}"}
    with tempfile.TemporaryDirectory(prefix="kickoutchi-release-e2e-") as temporary:
        destination = Path(temporary)
        if suffix == ".zip":
            binaries = extract_zip_binaries(archive, destination, target, expected)
        else:
            binaries = extract_tar_binaries(archive, destination, target, expected)
        if set(binaries) != expected:
            fail(
                "release archive binaries differ: "
                f"expected {sorted(expected)}, found {sorted(binaries)}"
            )

        canonical = binaries[f"kickoutchi{executable_suffix}"]
        short = binaries[f"kick{executable_suffix}"]
        run_version(canonical, expected_version)
        run_version(short, expected_version)

        environment = os.environ.copy()
        environment["KICKOUTCHI_RELEASE_E2E_REQUIRED"] = "1"
        environment["KICKOUTCHI_E2E_KICKOUTCHI"] = str(canonical)
        environment["KICKOUTCHI_E2E_KICK"] = str(short)
        if runner_os == "Linux":
            environment["KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES"] = "1"
        subprocess.run(
            ["cargo", "test", "--locked", "--all-features", "--test", "cli_contract"],
            check=True,
            env=environment,
            timeout=TEST_TIMEOUT_SECONDS,
        )

    return {
        "artifact_e2e": "passed",
        "archive": archive.name,
        "archive_bytes": archive_size,
        "archive_sha256": archive_sha256,
        "native_target": target,
        "binaries": sorted(expected),
        "capability_policy": (
            "required" if runner_os == "Linux" else "explicit_product_result"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--distrib", required=True, type=Path)
    parser.add_argument("--targets-json", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--runner-arch", required=True)
    arguments = parser.parse_args()
    result = validate_release_artifact(
        arguments.distrib,
        arguments.targets_json,
        arguments.runner_os,
        arguments.runner_arch,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
