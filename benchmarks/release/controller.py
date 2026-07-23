#!/usr/bin/env python3
import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import platform
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO

if __package__:
    from .common import (
        ARTIFACT_BYTES_MAX,
        PLAN_BYTES_MAX,
        EvidenceError,
        balanced_orders,
        canonical_json,
        read_json,
        require_absent,
        sha256_bytes,
        validate_plan,
    )
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from benchmarks.release.common import (  # type: ignore[no-redef]
        ARTIFACT_BYTES_MAX,
        PLAN_BYTES_MAX,
        EvidenceError,
        balanced_orders,
        canonical_json,
        read_json,
        require_absent,
        sha256_bytes,
        validate_plan,
    )


def snapshot_executable(source: Path, directory: Path, name: str, maximum: int) -> tuple[Path, str, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        raise EvidenceError(f"could not open {name} binary: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1:
            raise EvidenceError(f"{name} binary is not a nonempty regular file")
        if metadata.st_size > maximum or metadata.st_size > ARTIFACT_BYTES_MAX:
            raise EvidenceError(f"{name} binary exceeds the artifact bound")
        if os.name != "nt" and metadata.st_mode & 0o111 == 0:
            raise EvidenceError(f"{name} binary is not executable")
        destination = directory / (name + (".exe" if os.name == "nt" else ""))
        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(os.dup(descriptor), "rb") as input_file, destination.open("xb") as output_file:
            while True:
                chunk = input_file.read(min(1024 * 1024, maximum + 1 - copied))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > maximum:
                    raise EvidenceError(f"{name} binary exceeds the artifact bound")
                digest.update(chunk)
                output_file.write(chunk)
            output_file.flush()
            os.fsync(output_file.fileno())
        if copied != metadata.st_size:
            raise EvidenceError(f"{name} binary changed while its private snapshot was created")
        if os.name != "nt":
            destination.chmod(0o700)
        return destination, digest.hexdigest(), copied
    finally:
        os.close(descriptor)


def _wait_process(
    process: subprocess.Popen[bytes], timeout: float, stdout: BinaryIO,
    stderr: BinaryIO, output_max: int,
) -> tuple[int, int | None, int | None, int | None, bool, bool]:
    deadline = time.monotonic() + timeout
    timed_out = False
    oversized = False

    def output_too_large() -> bool:
        return os.fstat(stdout.fileno()).st_size > output_max or os.fstat(stderr.fileno()).st_size > output_max

    if os.name == "posix":
        usage = None
        status = 0
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                break
            if output_too_large():
                oversized = True
                process.kill()
                _, status, usage = os.wait4(process.pid, 0)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                process.kill()
                _, status, usage = os.wait4(process.pid, 0)
                break
            time.sleep(0.002)
        returncode = os.waitstatus_to_exitcode(status)
        process.returncode = returncode
        peak = usage.ru_maxrss * (1024 if sys.platform.startswith("linux") else 1)
        return returncode, int(usage.ru_utime * 1e9), int(usage.ru_stime * 1e9), peak if sys.platform.startswith("linux") else None, timed_out, oversized

    while process.poll() is None and time.monotonic() < deadline:
        if output_too_large():
            oversized = True
            process.kill()
            break
        time.sleep(0.002)
    if process.poll() is None:
        timed_out = True
        process.kill()
    process.wait()
    user_ns, system_ns, peak = _windows_usage(process)
    return process.returncode, user_ns, system_ns, peak, timed_out, oversized


def _windows_usage(process: subprocess.Popen[bytes]) -> tuple[int | None, int | None, int | None]:
    if os.name != "nt":
        return None, None, None
    try:
        class FileTime(ctypes.Structure):
            _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_uint32), ("PageFaultCount", ctypes.c_uint32),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        creation, exit_time, kernel, user = FileTime(), FileTime(), FileTime(), FileTime()
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        handle = int(process._handle)  # type: ignore[attr-defined]
        get_times = ctypes.windll.kernel32.GetProcessTimes
        get_memory = ctypes.windll.psapi.GetProcessMemoryInfo
        times_ok = get_times(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user))
        memory_ok = get_memory(handle, ctypes.byref(counters), counters.cb)
        ticks = lambda value: (value.high << 32) | value.low
        return (
            ticks(user) * 100 if times_ok else None,
            ticks(kernel) * 100 if times_ok else None,
            int(counters.PeakWorkingSetSize) if memory_ok else None,
        )
    except (AttributeError, OSError, ValueError):
        return None, None, None


def invoke(binary: Path, arguments: list[str], environment: dict[str, str], timeout: int, output_max: int) -> dict[str, Any]:
    started = time.monotonic_ns()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                [str(binary), *arguments], stdin=subprocess.DEVNULL, stdout=stdout,
                stderr=stderr, env=environment, close_fds=True,
            )
            try:
                status, user_ns, system_ns, peak, timed_out, oversized = _wait_process(
                    process, timeout, stdout, stderr, output_max
                )
            except BaseException:
                try:
                    process.kill()
                except OSError:
                    pass
                try:
                    process.wait()
                except (ChildProcessError, OSError):
                    pass
                raise
        except OSError as error:
            return {"status": 255, "latency_ns": time.monotonic_ns() - started, "user_cpu_ns": None,
                    "system_cpu_ns": None, "peak_memory_bytes": None, "stdout": b"", "stderr": str(error).encode(), "timed_out": False}
        elapsed = time.monotonic_ns() - started
        stdout.seek(0, os.SEEK_END)
        stdout_size = stdout.tell()
        stderr.seek(0, os.SEEK_END)
        stderr_size = stderr.tell()
        if oversized or stdout_size > output_max or stderr_size > output_max:
            return {"status": status, "latency_ns": elapsed, "user_cpu_ns": user_ns,
                    "system_cpu_ns": system_ns, "peak_memory_bytes": peak, "stdout": b"", "stderr": b"output bound exceeded", "timed_out": timed_out, "oversized": True}
        stdout.seek(0)
        stderr.seek(0)
        return {"status": status, "latency_ns": elapsed, "user_cpu_ns": user_ns,
                "system_cpu_ns": system_ns, "peak_memory_bytes": peak, "stdout": stdout.read(),
                "stderr": stderr.read(), "timed_out": timed_out, "oversized": False}


def validate_output(kind: str, result: dict[str, Any], expected_endpoints: set[tuple[str, str, int]]) -> tuple[bool, int, int, str | None]:
    if result.get("oversized"):
        return False, 0, 0, "output_bound_exceeded"
    if result["timed_out"]:
        return False, 0, 0, "timeout"
    try:
        if kind == "watch":
            documents = [json.loads(line) for line in result["stdout"].splitlines() if line]
            valid = len(documents) == 1 and all(
                isinstance(item, dict) and item.get("schema") == "kickoutchi.watch_event"
                and item.get("version") == 1 and item.get("sequence") == index
                for index, item in enumerate(documents)
            ) and documents[0].get("event") == "baseline"
            if valid and expected_endpoints:
                data = documents[0].get("data")
                endpoint = data.get("endpoint") if isinstance(data, dict) else None
                valid = isinstance(endpoint, dict) and (
                    endpoint.get("protocol"), endpoint.get("address"), endpoint.get("port")
                ) in expected_endpoints
            return valid and result["status"] == 0, 0, len(documents), None if valid else "invalid_watch_output"
        document = json.loads(result["stdout"])
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as error:
        return False, 0, 0, f"invalid_json:{error}"
    if kind == "list":
        if result["status"] != 0 or not isinstance(document, list):
            return False, 0, 0, "invalid_list_output"
        if any(
            not isinstance(row, dict) or row.get("protocol") not in {"tcp", "udp"}
            or not isinstance(row.get("local_addr"), str)
            or isinstance(row.get("local_port"), bool) or not isinstance(row.get("local_port"), int)
            or not 1 <= row["local_port"] <= 65535 or row.get("state") not in {"listen", "bound"}
            for row in document
        ):
            return False, 0, 0, "invalid_list_row"
        observed = {(row.get("protocol"), row.get("local_addr"), row.get("local_port")) for row in document if isinstance(row, dict)}
        valid = expected_endpoints <= observed
        return valid, len(document), 0, None if valid else "helper_endpoints_missing"
    if kind == "snapshot":
        valid = isinstance(document, dict) and result["status"] == 0 and document.get("schema") == "kickoutchi.snapshot" and document.get("version") == 1 and isinstance(document.get("sockets"), list)
        return valid, len(document.get("sockets", [])) if valid else 0, 0, None if valid else "invalid_snapshot_output"
    results = document.get("results") if isinstance(document, dict) else None
    valid = isinstance(document, dict) and result["status"] in {0, 3} and document.get("schema") == "kickoutchi.why" and document.get("version") == 1 and isinstance(results, list) and len(results) == 8 and document.get("aggregate_exit_code") == result["status"]
    return valid, len(document.get("results", [])) if valid else 0, 0, None if valid else "invalid_why_output"


def helper_sockets(count: int) -> tuple[list[socket.socket], set[tuple[str, str, int]]]:
    owned: list[socket.socket] = []
    endpoints: set[tuple[str, str, int]] = set()
    variants = ((socket.AF_INET, socket.SOCK_STREAM, "tcp", "127.0.0.1"),
                (socket.AF_INET, socket.SOCK_DGRAM, "udp", "127.0.0.1"),
                (socket.AF_INET6, socket.SOCK_STREAM, "tcp", "::1"),
                (socket.AF_INET6, socket.SOCK_DGRAM, "udp", "::1"))
    try:
        for family, kind, protocol, address in variants:
            for _ in range(count):
                item = socket.socket(family, kind)
                item.set_inheritable(False)
                item.bind((address, 0))
                if kind == socket.SOCK_STREAM:
                    item.listen(1)
                endpoints.add((protocol, address, item.getsockname()[1]))
                owned.append(item)
        return owned, endpoints
    except OSError as error:
        for item in owned:
            item.close()
        raise EvidenceError(f"could not establish all controlled IPv4/IPv6 TCP/UDP sockets: {error}") from error


def command_for(workload: dict[str, Any], why_port: int | None, watch_port: int | None) -> list[str]:
    command = list(workload["semantics"]["command"])
    replacements = {
        "{controller_selected_port}": why_port,
        "{controller_watch_port}": watch_port,
    }
    return [str(replacements[value]) if value in replacements else value for value in command]


def choose_why_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as item:
        item.bind(("127.0.0.1", 0))
        return item.getsockname()[1]


def git_commit() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as error:
        raise EvidenceError(f"could not validate candidate source identity: {error}") from error
    return result.stdout.strip()


def physical_memory_bytes() -> int | None:
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, OSError, ValueError):
        return None


def load_average() -> list[float] | None:
    try:
        return list(os.getloadavg())
    except (AttributeError, OSError):
        return None


def smoke_workload(workload: dict[str, Any]) -> dict[str, Any]:
    changed = dict(workload)
    changed["blocks"] = 1
    changed["samples_per_block"] = 4 if workload["comparison"] == "baseline_candidate" else 2
    changed["warmups"] = 1
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect bounded native release benchmark evidence.")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new raw JSONL path")
    parser.add_argument("--manifest", required=True, type=Path, help="new manifest JSON path")
    parser.add_argument("--smoke", action="store_true", help="small non-gate run for local validation")
    args = parser.parse_args(argv)
    try:
        plan, plan_bytes = read_json(args.plan, PLAN_BYTES_MAX)
        validate_plan(plan)
        output = args.output.absolute()
        manifest_path = args.manifest.absolute()
        output.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        require_absent(output, manifest_path)
        harness_commit = git_commit()
        started_wall = dt.datetime.now(dt.timezone.utc).isoformat()
        started_mono = time.monotonic()
        bounds = plan["bounds"]
        mode = "smoke" if args.smoke else "final"
        gate_eligible = not args.smoke
        with tempfile.TemporaryDirectory(prefix="kickoutchi-release-artifacts-") as artifact_dir_name, tempfile.TemporaryDirectory(prefix="kickoutchi-release-env-") as env_dir_name, tempfile.TemporaryDirectory(prefix=f".{output.name}.", dir=output.parent) as evidence_dir_name:
            artifact_dir = Path(artifact_dir_name)
            baseline, baseline_hash, baseline_size = snapshot_executable(args.baseline, artifact_dir, "baseline", bounds["artifact_bytes_max"])
            candidate, candidate_hash, candidate_size = snapshot_executable(args.candidate, artifact_dir, "candidate", bounds["artifact_bytes_max"])
            platform_key = f"{platform.system().lower()}-{platform.machine().lower()}"
            for role, digest in (("baseline", baseline_hash), ("candidate", candidate_hash)):
                expected = plan["artifacts"][role]["sha256_by_platform"].get(platform_key)
                if not expected:
                    raise EvidenceError(f"{role} artifact hash is not declared for {platform_key}")
                if expected != digest:
                    raise EvidenceError(f"{role} artifact hash does not match the plan for {platform_key}")
            environment = {"LC_ALL": "C", "LANG": "C", "HOME": env_dir_name, "XDG_CONFIG_HOME": env_dir_name,
                           "TMPDIR": env_dir_name, "TEMP": env_dir_name, "TMP": env_dir_name}
            if os.name == "nt":
                environment["SystemRoot"] = os.environ.get("SystemRoot", "C:\\Windows")
            versions: dict[str, str] = {}
            for role, binary, expected in (("baseline", baseline, "1.2.0"), ("candidate", candidate, "1.3.0")):
                result = invoke(binary, ["--version"], environment, bounds["child_timeout_seconds"], bounds["output_bytes_max"])
                try:
                    text = result["stdout"].decode("utf-8", "strict").strip() if result["status"] == 0 else ""
                except UnicodeDecodeError as error:
                    raise EvidenceError(f"{role} version output is not UTF-8") from error
                if text != f"kickoutchi {expected}":
                    raise EvidenceError(f"{role} version output is {text!r}, expected 'kickoutchi {expected}'")
                versions[role] = text
            temp_raw = Path(evidence_dir_name) / "raw.jsonl"
            row_count = failures = 0
            commands: dict[str, list[str]] = {}
            workload_counts: dict[str, int] = {}
            with temp_raw.open("xb") as raw:
                for declared_workload in plan["workloads"]:
                    workload = smoke_workload(declared_workload) if args.smoke else declared_workload
                    if time.monotonic() - started_mono > bounds["run_timeout_seconds"]:
                        raise EvidenceError("run timeout reached before workload start")
                    owned: list[socket.socket] = []
                    endpoints: set[tuple[str, str, int]] = set()
                    try:
                        if workload["kind"] == "list":
                            owned, endpoints = helper_sockets(workload["semantics"]["sockets_per_variant"])
                        watch_port = None
                        if workload["kind"] == "watch":
                            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            owned.append(listener)
                            listener.set_inheritable(False)
                            listener.bind(("127.0.0.1", 0))
                            listener.listen(1)
                            watch_port = listener.getsockname()[1]
                            endpoints.add(("tcp", "127.0.0.1", watch_port))
                        why_port = choose_why_port() if workload["kind"] == "why" else None
                        command = command_for(workload, why_port, watch_port)
                        commands[workload["name"]] = command
                        applicable = [("baseline", baseline), ("candidate", candidate)] if workload["comparison"] == "baseline_candidate" else [("candidate", candidate)]
                        for role, binary in applicable:
                            preflight = invoke(binary, command, environment, bounds["child_timeout_seconds"], bounds["output_bytes_max"])
                            valid, _, _, error = validate_output(workload["kind"], preflight, endpoints)
                            if not valid:
                                raise EvidenceError(f"{workload['name']} {role} preflight failed: {error}")
                        samples_by_key: dict[tuple[str, str], int] = {}

                        def record(comparison: str, role: str, lane_side: str, binary: Path, block: int, pair: int, order: int) -> None:
                            nonlocal row_count, failures
                            if time.monotonic() - started_mono > bounds["run_timeout_seconds"]:
                                raise EvidenceError("run timeout reached during collection")
                            result = invoke(binary, command, environment, bounds["child_timeout_seconds"], bounds["output_bytes_max"])
                            valid, rows, events, error = validate_output(workload["kind"], result, endpoints)
                            samples_by_key[(comparison, role)] = samples_by_key.get((comparison, role), 0) + 1
                            row = {
                                "schema": "kickoutchi.release_observation", "version": 1, "plan_sha256": sha256_bytes(plan_bytes),
                                "mode": mode, "gate_eligible": gate_eligible, "workload": workload["name"], "comparison": comparison,
                                "artifact_role": role, "lane_side": lane_side,
                                "artifact_sha256": baseline_hash if role == "baseline" else candidate_hash,
                                "artifact_bytes": baseline_size if role == "baseline" else candidate_size, "block": block, "pair": pair,
                                "order": order, "sample": samples_by_key[(comparison, role)], "command": command,
                                "latency_ns": result["latency_ns"], "user_cpu_ns": result["user_cpu_ns"],
                                "system_cpu_ns": result["system_cpu_ns"], "peak_memory_bytes": result["peak_memory_bytes"],
                                "status": result["status"], "outcome": "valid" if valid else "error", "error": error,
                                "stdout_bytes": len(result["stdout"]), "output_sha256": sha256_bytes(result["stdout"]),
                                "row_count": rows, "event_count": events,
                            }
                            raw.write(canonical_json(row))
                            row_count += 1
                            failures += int(not valid)
                            if failures >= bounds["max_failures"]:
                                raise EvidenceError("measured failure stop limit reached")

                        for block in range(1, workload["blocks"] + 1):
                            for role, binary in applicable:
                                for _ in range(workload["warmups"]):
                                    warmup = invoke(binary, command, environment, bounds["child_timeout_seconds"], bounds["output_bytes_max"])
                                    valid, _, _, error = validate_output(workload["kind"], warmup, endpoints)
                                    if not valid:
                                        raise EvidenceError(f"{workload['name']} {role} block {block} warmup failed: {error}")
                            orders = balanced_orders(plan["ordering_seed"], workload["name"], block, workload["samples_per_block"])
                            for pair, order_names in enumerate(orders, 1):
                                if workload["comparison"] == "baseline_candidate":
                                    lanes = (("aa", {"left": ("baseline", baseline), "right": ("baseline", baseline)}),
                                             ("ab", {"left": ("baseline", baseline), "right": ("candidate", candidate)}))
                                    for comparison, lane in lanes:
                                        for position, side in enumerate(order_names, 1):
                                            role, binary = lane[side]
                                            record(comparison, role, side, binary, block, pair, position)
                                else:
                                    record("candidate_only", "candidate", "candidate", candidate, block, pair, 1)
                        workload_counts[workload["name"]] = sum(value for key, value in samples_by_key.items())
                    finally:
                        for item in owned:
                            item.close()
                raw.flush()
                os.fsync(raw.fileno())
            raw_bytes = temp_raw.read_bytes()
            manifest = {
                "schema": "kickoutchi.release_benchmark_manifest", "version": 1, "plan_sha256": sha256_bytes(plan_bytes),
                "raw_sha256": sha256_bytes(raw_bytes), "mode": mode, "gate_eligible": gate_eligible, "complete": True,
                "started_utc": started_wall, "completed_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "duration_ns": int((time.monotonic() - started_mono) * 1e9),
                "source_commit": plan["artifacts"]["candidate"]["source_commit"],
                "harness_commit": harness_commit,
                "platform_key": platform_key, "platform": platform.platform(), "python": platform.python_version(),
                "cpu": platform.processor() or "unavailable", "cpu_count": os.cpu_count(),
                "physical_memory_bytes": physical_memory_bytes(), "load_average": load_average(),
                "environment": environment, "commands": commands, "versions": versions,
                "artifacts": {"baseline": {"sha256": baseline_hash, "bytes": baseline_size},
                              "candidate": {"sha256": candidate_hash, "bytes": candidate_size}},
                "row_count": row_count, "failure_count": failures, "workload_row_counts": workload_counts,
                "notes": ["Smoke mode is non-gate evidence."] if args.smoke else [],
            }
            temp_manifest = Path(evidence_dir_name) / "manifest.json"
            with temp_manifest.open("xb") as file:
                file.write(canonical_json(manifest)); file.flush(); os.fsync(file.fileno())
            try:
                os.link(temp_raw, output)
                os.link(temp_manifest, manifest_path)
            except FileExistsError as error:
                raise EvidenceError(f"output appeared during publication: {error.filename}") from error
        print(f"wrote {row_count} observations to {output} and manifest to {manifest_path}")
        return int(failures != 0)
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
