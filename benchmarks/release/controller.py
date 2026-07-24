#!/usr/bin/env python3
import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import platform
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

if __package__:
    from .common import ARTIFACT_BYTES_MAX, PLAN_BYTES_MAX, EvidenceError, balanced_orders, canonical_json, read_json, require_absent, sha256_bytes, validate_plan
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from benchmarks.release.common import ARTIFACT_BYTES_MAX, PLAN_BYTES_MAX, EvidenceError, balanced_orders, canonical_json, read_json, require_absent, sha256_bytes, validate_plan


def snapshot_executable(source: Path, directory: Path, name: str, maximum: int) -> tuple[Path, str, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        raise EvidenceError(f"could not open {name} binary: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= min(maximum, ARTIFACT_BYTES_MAX):
            raise EvidenceError(f"{name} binary is not a bounded nonempty regular file")
        if os.name != "nt" and metadata.st_mode & 0o111 == 0:
            raise EvidenceError(f"{name} binary is not executable")
        destination = directory / (name + (".exe" if os.name == "nt" else ""))
        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(os.dup(descriptor), "rb") as source_file, destination.open("xb") as output:
            while copied <= maximum:
                chunk = source_file.read(min(1024 * 1024, maximum + 1 - copied))
                if not chunk:
                    break
                copied += len(chunk)
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if copied != metadata.st_size:
            raise EvidenceError(f"{name} binary changed or exceeded its bound while copied")
        if os.name != "nt":
            destination.chmod(0o700)
        return destination, digest.hexdigest(), copied
    finally:
        os.close(descriptor)


class _Capture:
    def __init__(self, retained_max: int, stream_max: int) -> None:
        self.retained_max = retained_max
        self.stream_max = stream_max
        self.retained = bytearray()
        self.total = 0
        self.digest = hashlib.sha256()
        self.exceeded = threading.Event()

    def read(self, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                remaining = max(self.stream_max + 1 - self.total, 0)
                bounded = chunk[:remaining]
                self.total += len(bounded)
                self.digest.update(bounded)
                if len(self.retained) < self.retained_max:
                    self.retained.extend(bounded[: self.retained_max - len(self.retained)])
                if len(chunk) > remaining or self.total > self.stream_max:
                    self.exceeded.set()
        finally:
            stream.close()


class _WindowsJob:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.handle: int | None = None
        if os.name != "nt":
            return
        kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle or not kernel32.AssignProcessToJobObject(handle, ctypes.c_void_p(int(process._handle))):  # type: ignore[attr-defined]
            if handle:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
            raise EvidenceError(f"could not assign child to a Windows Job Object: {ctypes.get_last_error()}")
        self.handle = int(handle)

    def terminate(self) -> None:
        if self.handle is None:
            return
        kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
        kernel32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel32.TerminateJobObject.restype = ctypes.c_int
        kernel32.TerminateJobObject(ctypes.c_void_p(self.handle), 1)

    def close(self) -> None:
        if self.handle is not None:
            kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int
            kernel32.CloseHandle(ctypes.c_void_p(self.handle))
            self.handle = None


def _terminate_tree(process: subprocess.Popen[bytes], job: _WindowsJob) -> None:
    if os.name == "nt":
        job.terminate()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _windows_usage(process: subprocess.Popen[bytes]) -> tuple[int | None, int | None, int | None]:
    if os.name != "nt":
        return None, None, None
    class FileTime(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]
    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_uint32), ("PageFaultCount", ctypes.c_uint32), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    psapi = getattr(ctypes, "WinDLL")("psapi", use_last_error=True)
    kernel32.GetProcessTimes.argtypes = [ctypes.c_void_p, ctypes.POINTER(FileTime), ctypes.POINTER(FileTime), ctypes.POINTER(FileTime), ctypes.POINTER(FileTime)]
    kernel32.GetProcessTimes.restype = ctypes.c_int
    psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_uint32]
    psapi.GetProcessMemoryInfo.restype = ctypes.c_int
    creation, exit_time, kernel, user = FileTime(), FileTime(), FileTime(), FileTime()
    counters = Counters(cb=ctypes.sizeof(Counters))
    handle = ctypes.c_void_p(int(process._handle))  # type: ignore[attr-defined]
    times_ok = kernel32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user))
    memory_ok = psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
    ticks = lambda value: (value.high << 32) | value.low
    return ticks(user) * 100 if times_ok else None, ticks(kernel) * 100 if times_ok else None, int(counters.PeakWorkingSetSize) if memory_ok else None


def invoke(binary: Path, arguments: list[str], environment: dict[str, str], timeout: float, retained_max: int, stream_max: int) -> dict[str, Any]:
    started = time.monotonic_ns()
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    try:
        process = subprocess.Popen([str(binary), *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=environment, close_fds=True, start_new_session=os.name != "nt", creationflags=creationflags)
    except OSError as error:
        return {"status": 255, "latency_ns": time.monotonic_ns() - started, "user_cpu_ns": None, "system_cpu_ns": None,
                "peak_memory_bytes": None, "stdout": b"", "stderr": str(error).encode(), "stdout_bytes": 0, "stderr_bytes": len(str(error).encode()),
                "stdout_sha256": sha256_bytes(b""), "stderr_sha256": sha256_bytes(str(error).encode()), "timed_out": False, "stream_exceeded": False}
    try:
        job = _WindowsJob(process)
    except BaseException:
        process.kill()
        process.wait()
        raise
    stdout_capture, stderr_capture = _Capture(retained_max, stream_max), _Capture(retained_max, stream_max)
    threads = [threading.Thread(target=stdout_capture.read, args=(process.stdout,), daemon=True),
               threading.Thread(target=stderr_capture.read, args=(process.stderr,), daemon=True)]
    for thread in threads:
        thread.start()
    timed_out = False
    usage = None
    deadline = time.monotonic() + timeout
    try:
        if os.name == "posix":
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                if stdout_capture.exceeded.is_set() or stderr_capture.exceeded.is_set() or time.monotonic() >= deadline:
                    timed_out = time.monotonic() >= deadline
                    _terminate_tree(process, job)
                    _, status, usage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                time.sleep(0.002)
        else:
            while process.poll() is None:
                if stdout_capture.exceeded.is_set() or stderr_capture.exceeded.is_set() or time.monotonic() >= deadline:
                    timed_out = time.monotonic() >= deadline
                    _terminate_tree(process, job)
                    break
                time.sleep(0.002)
            process.wait()
        for thread in threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in threads):
            raise EvidenceError("bounded output reader did not finish after child cleanup")
        if usage is not None:
            user_ns, system_ns = int(usage.ru_utime * 1e9), int(usage.ru_stime * 1e9)
            peak = usage.ru_maxrss * (1024 if sys.platform.startswith("linux") else 1)
        else:
            user_ns, system_ns, peak = _windows_usage(process)
        return {"status": process.returncode, "latency_ns": time.monotonic_ns() - started, "user_cpu_ns": user_ns,
                "system_cpu_ns": system_ns, "peak_memory_bytes": peak, "stdout": bytes(stdout_capture.retained), "stderr": bytes(stderr_capture.retained),
                "stdout_bytes": stdout_capture.total, "stderr_bytes": stderr_capture.total, "stdout_sha256": stdout_capture.digest.hexdigest(),
                "stderr_sha256": stderr_capture.digest.hexdigest(), "timed_out": timed_out,
                "stream_exceeded": stdout_capture.exceeded.is_set() or stderr_capture.exceeded.is_set()}
    finally:
        if process.poll() is None:
            _terminate_tree(process, job)
            process.wait()
        job.close()


def _endpoint(document: Any) -> tuple[str, str, int] | None:
    if not isinstance(document, dict):
        return None
    protocol, address, port = document.get("protocol"), document.get("address"), document.get("port")
    return (protocol, address, port) if protocol in {"tcp", "udp"} and isinstance(address, str) and isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 else None


def validate_output(workload: dict[str, Any], result: dict[str, Any], expected_endpoints: set[tuple[str, str, int]], artifact_role: str = "candidate") -> tuple[bool, int, int, str | None, int | None, int | None]:
    expected = workload["expected"]
    if result["stream_exceeded"]:
        return False, 0, 0, "stream_bound_exceeded", None, None
    if result["timed_out"]:
        return False, 0, 0, "timeout", None, None
    if result["status"] not in expected["statuses"]:
        return False, 0, 0, "unexpected_status", None, None
    if expected["stderr_empty"] and result["stderr_bytes"] != 0:
        return False, 0, 0, "nonempty_stderr", None, None
    if result["stdout_bytes"] != len(result["stdout"]):
        return False, 0, 0, "output_not_retained_for_validation", None, None
    try:
        if workload["driver"] == "watch_fixture":
            document = json.loads(result["stdout"])
            keys = {"schema", "version", "scenario", "socket_count", "record_count", "change_event_count", "event_counts", "collection_attempts", "serialized_bytes", "checksum", "operation_duration_ns", "candidate_exit_code", "assertions_passed"}
            if not isinstance(document, dict) or set(document) != keys:
                return False, 0, 0, "invalid_fixture_helper_output", None, None
            integer_fields = ("socket_count", "record_count", "change_event_count", "collection_attempts", "serialized_bytes", "checksum", "operation_duration_ns", "candidate_exit_code")
            if any(not isinstance(document.get(field), int) or isinstance(document.get(field), bool) or document[field] < 0 for field in integer_fields):
                return False, 0, 0, "invalid_fixture_helper_output", None, None
            expected_exit = 1 if workload["name"] == "watch_failure_exhaustion" else 0
            attempts = {"snapshot_large":0, "snapshot_maximum":0, "watch_high_churn":2, "watch_transient_recovery":3, "watch_failure_exhaustion":4}[workload["name"]]
            event_counts = {"snapshot_large":{}, "snapshot_maximum":{}, "watch_high_churn":{"baseline":1024,"release":1024,"bind":1024}, "watch_transient_recovery":{"baseline":1,"collection_gap":1}, "watch_failure_exhaustion":{"baseline":1,"collection_gap":3}}[workload["name"]]
            valid = document["schema"] == "kickoutchi.release_fixture_helper" and document["version"] == 1 and document["scenario"] == workload["command"][0] and document["socket_count"] == workload["fixture"]["socket_count"] and document["record_count"] == (expected["rows"] if workload["kind"] == "snapshot" else expected["events"]) and document["change_event_count"] == workload["fixture"]["churn_events"] and document["event_counts"] == event_counts and document["collection_attempts"] == attempts and document["serialized_bytes"] > 0 and document["checksum"] > 0 and 0 < document["operation_duration_ns"] <= 120_000_000_000 and document["candidate_exit_code"] == expected_exit and document["assertions_passed"] is True
            rows = document["record_count"] if workload["kind"] == "snapshot" else 0
            events = document["change_event_count"] if workload["kind"] == "watch" else 0
            return (True, rows, events, None, document["operation_duration_ns"], None) if valid else (False, 0, 0, "invalid_fixture_helper_output", None, None)
        if workload["kind"] == "watch":
            documents = [json.loads(line) for line in result["stdout"].splitlines() if line]
            if len(documents) != expected["events"] or any(not isinstance(item, dict) or item.get("schema") != "kickoutchi.watch_event" or item.get("version") != 1 or item.get("sequence") != index for index, item in enumerate(documents)):
                return False, 0, 0, "invalid_watch_sequence", None, None
            if documents and documents[0].get("event") != "baseline":
                return False, 0, 0, "watch_missing_baseline", None, None
            return True, 0, len(documents), None, None, None
        document = json.loads(result["stdout"])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return False, 0, 0, f"invalid_json:{error}", None, None
    if workload["kind"] in {"list", "startup"}:
        required = {"protocol", "local_addr", "local_port", "state", "pid", "process_name", "executable_path", "command_line", "parent_pid", "parent_process_name", "child_pids", "protected", "platform", "permission", "label"}
        if artifact_role == "baseline":
            required.remove("label")
        if not isinstance(document, list) or any(not isinstance(row, dict) or set(row) != required or row.get("protocol") not in {"tcp", "udp"} or row.get("state") not in {"listen", "bound"} for row in document):
            return False, 0, 0, "invalid_list_contract", None, None
        observed = {(row["protocol"], row["local_addr"], row["local_port"]) for row in document}
        if expected["rows"] is not None and len(document) != expected["rows"]:
            return False, len(document), 0, "unexpected_row_count", None, None
        return (True, len(document), 0, None, None, None) if expected_endpoints <= observed else (False, len(document), 0, "helper_endpoints_missing", None, None)
    if workload["kind"] == "snapshot":
        keys = {"schema", "version", "capture", "scope", "completeness", "owner_completeness", "evidence_gaps", "omitted_evidence_gap_count", "sockets", "processes"}
        if not isinstance(document, dict) or set(document) != keys or document.get("schema") != "kickoutchi.snapshot" or document.get("version") != 1 or not isinstance(document.get("sockets"), list) or not isinstance(document.get("processes"), list) or not isinstance(document.get("evidence_gaps"), list) or not isinstance(document.get("omitted_evidence_gap_count"), int):
            return False, 0, 0, "invalid_snapshot_contract", None, None
        observed = {_endpoint(row.get("endpoint")) for row in document["sockets"] if isinstance(row, dict)}
        if expected["rows"] is not None and len(document["sockets"]) != expected["rows"]:
            return False, len(document["sockets"]), 0, "unexpected_row_count", None, None
        return (True, len(document["sockets"]), 0, None, None, None) if expected_endpoints <= observed else (False, len(document["sockets"]), 0, "snapshot_helper_endpoints_missing", None, None)
    if workload["kind"] == "why":
        results = document.get("results") if isinstance(document, dict) else None
        endpoints = [_endpoint(item.get("endpoint")) for item in results] if isinstance(results, list) else []
        probes_complete = isinstance(results, list) and all(isinstance(item, dict) and isinstance(item.get("verdict"), str) and item.get("certainty") in {"proven", "estimated", "heuristic", "unknown"} and isinstance(item.get("probe"), dict) and item["probe"].get("completed_unix_ms", -1) >= item["probe"].get("started_unix_ms", 0) for item in results)
        valid = isinstance(document, dict) and document.get("schema") == "kickoutchi.why" and document.get("version") == 1 and len(results or []) == 8 and len(set(endpoints)) == 8 and None not in endpoints and document.get("aggregate_exit_code") == result["status"] and probes_complete
        return valid, len(results or []), 0, None if valid else "invalid_why_matrix", None, None
    keys = {"schema", "version", "scenario", "input_sockets", "scanned_sockets", "events", "iterator_exhausted", "checksum", "engine_duration_ns"}
    input_sockets = document.get("input_sockets") if isinstance(document, dict) else None
    scanned_sockets = document.get("scanned_sockets") if isinstance(document, dict) else None
    engine_duration_ns = document.get("engine_duration_ns") if isinstance(document, dict) else None
    events = document.get("events") if isinstance(document, dict) else None
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in (input_sockets, scanned_sockets, events, engine_duration_ns)):
        return False, 0, 0, "invalid_diff_helper_output", None, None
    input_count, scan_count, event_count, duration_ns = input_sockets, scanned_sockets, events, engine_duration_ns
    if not isinstance(input_count, int) or not isinstance(scan_count, int) or not isinstance(event_count, int) or not isinstance(duration_ns, int):
        return False, 0, 0, "invalid_diff_helper_output", None, None
    valid = isinstance(document, dict) and set(document) == keys and document.get("schema") == "kickoutchi.release_diff_helper" and document.get("version") == 1 and document.get("scenario") == workload["command"][0] and input_count == workload["fixture"]["socket_count"] and scan_count == input_count * 2 and event_count == expected["events"] and document.get("iterator_exhausted") is True and isinstance(document.get("checksum"), int) and not isinstance(document.get("checksum"), bool) and 0 < duration_ns <= 120_000_000_000
    return (True, input_count, event_count, None, duration_ns, scan_count) if valid else (False, 0, 0, "invalid_diff_helper_output", None, None)


def helper_sockets(total: int) -> tuple[list[socket.socket], set[tuple[str, str, int]]]:
    variants = ((socket.AF_INET, socket.SOCK_STREAM, "tcp", "127.0.0.1"), (socket.AF_INET, socket.SOCK_DGRAM, "udp", "127.0.0.1"),
                (socket.AF_INET6, socket.SOCK_STREAM, "tcp", "::1"), (socket.AF_INET6, socket.SOCK_DGRAM, "udp", "::1"))
    owned: list[socket.socket] = []
    endpoints: set[tuple[str, str, int]] = set()
    try:
        for index in range(total):
            family, kind, protocol_name, address = variants[index % len(variants)]
            item = socket.socket(family, kind)
            item.set_inheritable(False)
            item.bind((address, 0))
            if kind == socket.SOCK_STREAM:
                item.listen(1)
            owned.append(item)
            endpoints.add((protocol_name, address, item.getsockname()[1]))
        return owned, endpoints
    except OSError as error:
        for item in owned:
            item.close()
        raise EvidenceError(f"could not create controlled socket fixture: {error}") from error


def verify_empty_linux_namespace() -> dict[str, Any]:
    parent = os.environ.get("KICKOUTCHI_PARENT_NETNS")
    try:
        current = os.readlink("/proc/self/ns/net")
    except OSError as error:
        raise EvidenceError(f"could not identify the benchmark network namespace: {error}") from error
    pattern = re.compile(r"net:\[[1-9][0-9]*\]")
    if parent is None or pattern.fullmatch(parent) is None or pattern.fullmatch(current) is None or parent == current:
        raise EvidenceError("benchmark process is not in a verified child network namespace")
    tables: dict[str, int] = {}
    for name in ("tcp", "tcp6", "udp", "udp6"):
        path = Path("/proc/net") / name
        try:
            lines = [line for line in path.read_text(encoding="ascii").splitlines() if line.strip()]
        except (OSError, UnicodeError) as error:
            raise EvidenceError(f"could not verify empty namespace table {name}: {error}") from error
        rows = max(len(lines) - 1, 0)
        tables[name] = rows
        if rows != 0:
            raise EvidenceError(f"isolated network namespace {name} table is not empty")
    return {"kind":"linux_network_namespace","method":"unshare","parent_identifier":parent,"identifier":current,"initial_rows":tables}


def environment_metadata() -> dict[str, Any]:
    rustc = subprocess.run(["rustc", "--version", "--verbose"], capture_output=True, text=True, timeout=10, check=False)
    power_files = [Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"), Path("/sys/class/power_supply/AC/online")]
    thermal_files = list(Path("/sys/class/thermal").glob("thermal_zone*/temp"))[:16] if Path("/sys/class/thermal").exists() else []
    def values(paths: list[Path]) -> dict[str, str]:
        result = {}
        for path in paths:
            try:
                result[str(path)] = path.read_text(encoding="ascii").strip()
            except (OSError, UnicodeError):
                result[str(path)] = "unavailable"
        return result
    if os.name == "nt":
        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_uint32), ("memory_load", ctypes.c_uint32), ("total_physical", ctypes.c_uint64),
                        ("available_physical", ctypes.c_uint64), ("total_page_file", ctypes.c_uint64), ("available_page_file", ctypes.c_uint64),
                        ("total_virtual", ctypes.c_uint64), ("available_virtual", ctypes.c_uint64), ("available_extended_virtual", ctypes.c_uint64)]
        kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
        kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MemoryStatus)]
        kernel32.GlobalMemoryStatusEx.restype = ctypes.c_int
        memory = MemoryStatus(length=ctypes.sizeof(MemoryStatus))
        ram = int(memory.total_physical) if kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)) else None
    else:
        try:
            ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        except (AttributeError, OSError, ValueError):
            ram = None
    try:
        load = list(os.getloadavg())
    except (AttributeError, OSError):
        load = None
    return {"compiler": rustc.stdout.strip() or "unavailable", "target": platform.machine(), "cpu": platform.processor() or "unavailable",
            "cpu_count": os.cpu_count(), "ram_bytes": ram, "os": platform.platform(), "kernel": platform.release(), "power": values(power_files),
            "thermal": values(thermal_files), "concurrent_load": load, "python": platform.python_version()}


def _git_commit() -> str:
    root = Path(__file__).resolve().parent.parent.parent
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10, check=False)
    if result.returncode or len(result.stdout.strip()) != 40:
        raise EvidenceError("could not record harness source commit")
    return result.stdout.strip()


def _tree_hash(paths: list[Path], base: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(base).as_posix().encode("utf-8")
        contents = path.read_bytes().replace(b"\r\n", b"\n")
        digest.update(len(relative).to_bytes(4, "big")); digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big")); digest.update(contents)
    return digest.hexdigest()


def _commit_tree_hash(commit: str, paths: list[Path], base: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(base).as_posix()
        result = subprocess.run(["git", "-c", f"safe.directory={base}", "show", f"{commit}:{relative}"], cwd=base, capture_output=True, timeout=10, check=False)
        if result.returncode:
            raise EvidenceError(f"could not read reviewed harness source {relative}")
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big")); digest.update(encoded)
        digest.update(len(result.stdout).to_bytes(8, "big")); digest.update(result.stdout)
    return digest.hexdigest()


def _commit_file_hash(commit: str, path: Path, base: Path) -> str:
    relative = path.relative_to(base).as_posix()
    result = subprocess.run(["git", "-c", f"safe.directory={base}", "show", f"{commit}:{relative}"], cwd=base, capture_output=True, timeout=10, check=False)
    if result.returncode:
        raise EvidenceError(f"could not read reviewed harness source {relative}")
    return sha256_bytes(result.stdout)


def verify_protocol_identity(plan: dict[str, Any]) -> None:
    identity = plan["protocol_identity"]
    release_dir = Path(__file__).resolve().parent
    root = release_dir.parent.parent
    harness_sources = [release_dir / "common.py", release_dir / "controller.py", release_dir / "summarize.py"]
    helper_sources = [release_dir / "diff_helper" / "Cargo.toml", release_dir / "diff_helper" / "src" / "main.rs", release_dir / "diff_helper" / "src" / "fixture_adapter.rs"]
    product_sources = [root / "src" / name for name in ("cli/watch.rs", "display.rs", "labels.rs", "model.rs", "observation.rs", "protection.rs", "public_output.rs", "query.rs", "watch.rs")]
    lock_path = release_dir / "diff_helper" / "Cargo.lock"
    harness_hash = _tree_hash(harness_sources, root)
    helper_source_hash = _tree_hash(helper_sources, root)
    product_hash = _tree_hash(product_sources, root)
    lock_hash = sha256_bytes(lock_path.read_bytes())
    rustc = subprocess.run(["rustc", "--version", "--verbose"], capture_output=True, text=True, timeout=10, check=False)
    lines = rustc.stdout.splitlines()
    rustc_version = lines[0] if rustc.returncode == 0 and lines else None
    rust_target = next((line.removeprefix("host: ") for line in lines if line.startswith("host: ")), None)
    platform_key = f"{platform.system().lower()}-{platform.machine().lower()}"
    actual = {"harness_tree_sha256":harness_hash,"included_product_sources_sha256":product_hash,
              "diff_helper_source_sha256":helper_source_hash,"diff_helper_lock_sha256":lock_hash,"rustc_version":rustc_version}
    for key, value in actual.items():
        if identity[key] != value:
            raise EvidenceError(f"protocol identity differs for {key}")
    if identity["rust_target_by_platform"].get(platform_key) != rust_target:
        raise EvidenceError("protocol identity differs for rust target")
    reviewed_commit = identity["harness_commit"]
    reviewed = {"harness_tree_sha256":_commit_tree_hash(reviewed_commit, harness_sources, root),
                "included_product_sources_sha256":_commit_tree_hash(reviewed_commit, product_sources, root),
                "diff_helper_source_sha256":_commit_tree_hash(reviewed_commit, helper_sources, root),
                "diff_helper_lock_sha256":_commit_file_hash(reviewed_commit, lock_path, root)}
    for key, value in reviewed.items():
        if identity[key] != value:
            raise EvidenceError(f"reviewed source commit differs for {key}")
    candidate_product_hash = _commit_tree_hash(plan["artifacts"]["candidate"]["source_commit"], product_sources, root)
    if identity["included_product_sources_sha256"] != candidate_product_hash:
        raise EvidenceError("included product sources differ from the candidate commit")


def smoke_workload(workload: dict[str, Any]) -> dict[str, Any]:
    changed = dict(workload)
    changed["sampling"] = dict(workload["sampling"], blocks=1, samples_per_block=4, warmups=1)
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect bounded native release benchmark evidence.")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--diff-helper", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args(argv)
    try:
        plan, plan_bytes = read_json(args.plan, PLAN_BYTES_MAX)
        validate_plan(plan, require_gate_ready=not args.smoke)
        if not args.smoke:
            verify_protocol_identity(plan)
        output, manifest_path = args.output.absolute(), args.manifest.absolute()
        output.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        require_absent(output, manifest_path)
        bounds = plan["bounds"]
        started_utc = dt.datetime.now(dt.timezone.utc).isoformat()
        started_mono = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="kickoutchi-release-artifacts-") as artifact_name, tempfile.TemporaryDirectory(prefix="kickoutchi-release-env-") as env_name, tempfile.TemporaryDirectory(prefix=f".{output.name}.", dir=output.parent) as evidence_name:
            artifact_dir = Path(artifact_name)
            baseline, baseline_hash, baseline_size = snapshot_executable(args.baseline, artifact_dir, "baseline", bounds["artifact_bytes_max"])
            candidate, candidate_hash, candidate_size = snapshot_executable(args.candidate, artifact_dir, "candidate", bounds["artifact_bytes_max"])
            helper = helper_hash = None
            helper_size = None
            if args.diff_helper:
                helper, helper_hash, helper_size = snapshot_executable(args.diff_helper, artifact_dir, "diff-helper", bounds["artifact_bytes_max"])
            platform_key = f"{platform.system().lower()}-{platform.machine().lower()}"
            for role, digest in (("baseline", baseline_hash), ("candidate", candidate_hash)):
                expected_hash = plan["artifacts"][role]["sha256_by_platform"].get(platform_key)
                if expected_hash != digest:
                    raise EvidenceError(f"{role} artifact hash is absent or differs for {platform_key}")
            if not args.smoke and plan["protocol_identity"]["diff_helper_sha256_by_platform"].get(platform_key) != helper_hash:
                raise EvidenceError(f"diff helper artifact hash is absent or differs for {platform_key}")
            base_environment = {"LC_ALL": "C", "LANG": "C", "HOME": env_name, "XDG_CONFIG_HOME": env_name, "TMPDIR": env_name, "TEMP": env_name, "TMP": env_name}
            if os.name == "nt":
                base_environment["SystemRoot"] = os.environ.get("SystemRoot", "C:\\Windows")
            versions = {}
            for role, binary, version in (("baseline", baseline, "1.2.0"), ("candidate", candidate, "1.3.0")):
                result = invoke(binary, ["--version"], base_environment, bounds["child_timeout_seconds"], bounds["retained_output_bytes_max"], bounds["stream_bytes_max"])
                text = result["stdout"].decode("utf-8", "strict").strip() if result["status"] == 0 and result["stderr_bytes"] == 0 else ""
                if text != f"kickoutchi {version}":
                    raise EvidenceError(f"{role} version output is invalid")
                versions[role] = text
            temp_raw = Path(evidence_name) / "raw.jsonl"
            commands: dict[str, list[str]] = {}
            skipped: list[str] = []
            not_applicable: list[str] = []
            fixture_scope: dict[str, Any] = {"kind":"native_host_stack","method":"none","parent_identifier":None,"identifier":None,"initial_rows":{}}
            row_count = failures = 0
            with temp_raw.open("xb") as raw:
                for declared in plan["workloads"]:
                    if not declared["implemented"]:
                        if args.smoke:
                            skipped.append(declared["name"])
                            continue
                        raise EvidenceError(f"unimplemented workload reached collection: {declared['name']}")
                    workload = smoke_workload(declared) if args.smoke else declared
                    if workload["driver"] == "namespace_fixture" and not sys.platform.startswith("linux"):
                        not_applicable.append(workload["name"])
                        continue
                    if workload["driver"] == "diff_helper" and helper is None:
                        if args.smoke:
                            skipped.append(workload["name"])
                            continue
                        raise EvidenceError("diff helper is required")
                    owned: list[socket.socket] = []
                    endpoints: set[tuple[str, str, int]] = set()
                    try:
                        if workload["driver"] == "namespace_fixture":
                            fixture_scope = verify_empty_linux_namespace()
                        if workload["driver"] == "native_cli":
                            owned, endpoints = helper_sockets(workload["fixture"]["socket_count"])
                        replacements: dict[str, int] = {}
                        if workload["kind"] == "why":
                            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            reservation.set_inheritable(False)
                            reservation.bind(("127.0.0.1", 0)); reservation.listen(1); owned.append(reservation)
                            replacements["{reserved_port}"] = reservation.getsockname()[1]
                        if workload["kind"] == "watch" and workload["driver"] == "native_cli":
                            replacements["{watch_port}"] = next(iter(endpoints))[2]
                        command = [str(replacements.get(value, value)) for value in workload["command"]]
                        commands[workload["name"]] = command
                        executable = helper if workload["driver"] in {"diff_helper", "watch_fixture"} else candidate
                        if executable is None:
                            raise EvidenceError(f"{workload['name']} has no executable driver")
                        if workload["driver"] in {"diff_helper", "watch_fixture"} and helper_size is None:
                            raise EvidenceError("diff helper size is unavailable")
                        applicable = [("candidate", executable)] if workload["comparison"] == "candidate_only" else [("baseline", baseline), ("candidate", candidate)]
                        for role, binary in applicable:
                            preflight = invoke(binary, command, base_environment, bounds["child_timeout_seconds"], bounds["retained_output_bytes_max"], bounds["stream_bytes_max"])
                            valid, _, _, error, _, _ = validate_output(workload, preflight, endpoints, role)
                            if not valid:
                                raise EvidenceError(f"{workload['name']} {role} preflight failed: {error}")
                        sample_counts: dict[tuple[str, str, str], int] = {}
                        def record(lane: str, role: str, side: str, binary: Path, block: int, pair: int, order: int) -> None:
                            nonlocal row_count, failures
                            environment = base_environment
                            cold_dir = None
                            if workload["startup"] == "cold":
                                cold_dir = tempfile.TemporaryDirectory(prefix="kickoutchi-cold-")
                                environment = dict(base_environment, HOME=cold_dir.name, XDG_CONFIG_HOME=cold_dir.name)
                            try:
                                result = invoke(binary, command, environment, bounds["child_timeout_seconds"], bounds["retained_output_bytes_max"], bounds["stream_bytes_max"])
                            finally:
                                if cold_dir:
                                    cold_dir.cleanup()
                            valid, rows, events, error, operation_duration_ns, scanned_count = validate_output(workload, result, endpoints, role)
                            key = (lane, role, side)
                            sample_counts[key] = sample_counts.get(key, 0) + 1
                            row = {"schema":"kickoutchi.release_observation","version":2,"plan_sha256":sha256_bytes(plan_bytes),"mode":"smoke" if args.smoke else "final","gate_eligible":not args.smoke,
                                   "workload":workload["name"],"lane":lane,"artifact_role":role,"lane_side":side,"executor_role":"source_helper" if workload["driver"] in {"diff_helper", "watch_fixture"} else role,"executor_sha256":helper_hash if workload["driver"] in {"diff_helper", "watch_fixture"} else (baseline_hash if role == "baseline" else candidate_hash),
                                    "executor_bytes":helper_size if workload["driver"] in {"diff_helper", "watch_fixture"} else (baseline_size if role == "baseline" else candidate_size),"block":block,"pair":pair,"order":order,"sample":sample_counts[key],"command":command,
                                   "latency_ns":result["latency_ns"],"user_cpu_ns":result["user_cpu_ns"],"system_cpu_ns":result["system_cpu_ns"],"peak_memory_bytes":result["peak_memory_bytes"],
                                    "status":result["status"],"outcome":"valid" if valid else "error","error":error,"stdout_bytes":result["stdout_bytes"],"stderr_bytes":result["stderr_bytes"],
                                    "stdout_sha256":result["stdout_sha256"],"stderr_sha256":result["stderr_sha256"],"row_count":rows,"event_count":events,
                                    "operation_duration_ns":operation_duration_ns,"scanned_count":scanned_count}
                            raw.write(canonical_json(row)); row_count += 1; failures += int(not valid)
                            if failures >= bounds["max_failures"]:
                                raise EvidenceError("measured failure stop limit reached")
                        sampling = workload["sampling"]
                        for block in range(1, sampling["blocks"] + 1):
                            for role, binary in applicable:
                                for _ in range(sampling["warmups"]):
                                    warmup = invoke(binary, command, base_environment, bounds["child_timeout_seconds"], bounds["retained_output_bytes_max"], bounds["stream_bytes_max"])
                                    if not validate_output(workload, warmup, endpoints, role)[0]:
                                        raise EvidenceError(f"{workload['name']} warmup failed")
                            pair_count = sampling["samples_per_block"] if workload["comparison"] == "baseline_candidate" else sampling["samples_per_block"] // 2
                            orders = balanced_orders(plan["ordering_seed"], workload["name"], block, pair_count)
                            for pair, sides in enumerate(orders, 1):
                                if workload["comparison"] == "baseline_candidate":
                                    lanes = (("calibration", {"left":("baseline",baseline),"right":("baseline",baseline)}), ("comparison", {"left":("baseline",baseline),"right":("candidate",candidate)}))
                                else:
                                    lanes = (("calibration", {"left":("candidate",executable),"right":("candidate",executable)}),)
                                for lane_name, lane in lanes:
                                    for position, side in enumerate(sides, 1):
                                        role, binary = lane[side]
                                        record(lane_name, role, side, binary, block, pair, position)
                    finally:
                        for item in owned:
                            item.close()
                    if time.monotonic() - started_mono > bounds["run_timeout_seconds"]:
                        raise EvidenceError("run timeout reached")
                raw.flush(); os.fsync(raw.fileno())
            raw_bytes = temp_raw.read_bytes()
            manifest = {"schema":"kickoutchi.release_benchmark_manifest","version":2,"plan_sha256":sha256_bytes(plan_bytes),"raw_sha256":sha256_bytes(raw_bytes),
                        "mode":"smoke" if args.smoke else "final","gate_eligible":not args.smoke,"complete":True,"started_utc":started_utc,
                        "duration_ns":int((time.monotonic()-started_mono)*1e9),"source_commit":plan["artifacts"]["candidate"]["source_commit"],
                        "harness_commit":plan["protocol_identity"]["harness_commit"],"checkout_commit":_git_commit(),
                        "platform_key":platform_key,"environment":environment_metadata(),"commands":commands,"versions":versions,"diff_helper_sha256":helper_hash,"diff_helper_bytes":helper_size,
                        "fixture_scope":fixture_scope,"not_applicable_workloads":not_applicable,
                        "artifacts":{"baseline":{"sha256":baseline_hash,"bytes":baseline_size},"candidate":{"sha256":candidate_hash,"bytes":candidate_size}},
                        "row_count":row_count,"failure_count":failures,"skipped_workloads":skipped,"notes":["Smoke mode is non-gate evidence and may skip unavailable integration drivers."] if args.smoke else []}
            temp_manifest = Path(evidence_name) / "manifest.json"
            with temp_manifest.open("xb") as file:
                file.write(canonical_json(manifest)); file.flush(); os.fsync(file.fileno())
            try:
                os.link(temp_raw, output); os.link(temp_manifest, manifest_path)
            except FileExistsError as error:
                raise EvidenceError(f"output appeared during publication: {error.filename}") from error
        print(f"wrote {row_count} observations; skipped {len(skipped)} unavailable smoke workloads")
        return int(failures != 0)
    except (EvidenceError, UnicodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
