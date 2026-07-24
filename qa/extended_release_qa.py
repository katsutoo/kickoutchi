#!/usr/bin/env python3
"""Additional bounded user-level charters for exact Kickoutchi artifacts."""

import argparse
import contextlib
import ctypes
import json
import os
import platform
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from qa import release_qa


REPORT_VERSION = 1
MEMORY_SAMPLES = 20
MEMORY_SAMPLE_SECONDS = 0.1
MEMORY_GROWTH_LIMIT_BYTES = 8 * 1024 * 1024


def _sha256(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("must be 64 lowercase hexadecimal characters")
    return value


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--candidate-sha256", required=True, type=_sha256)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--baseline-sha256", required=True, type=_sha256)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=release_qa._positive_float, default=15.0)
    parser.add_argument("--privileged-watch", action="store_true", help="run only the replacement lifecycle through sudo -n")
    parsed = parser.parse_args(argv)
    if len(parsed.candidate_commit) != 40 or any(c not in "0123456789abcdef" for c in parsed.candidate_commit):
        parser.error("candidate commit must be 40 lowercase hexadecimal characters")
    if parsed.privileged_watch and platform.system() != "Linux":
        parser.error("--privileged-watch is valid only on Linux")
    return parsed


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise release_qa.ProductFailure(message)


def _result_json(result: dict[str, Any], exits: set[int]) -> Any:
    release_qa._expect_exit(result, exits)
    return release_qa.parse_json_document(result)


def _endpoint(protocol: str, address: str, port: int) -> tuple[str, str, int]:
    return protocol, address, port


def validate_why_document(
    value: Any,
    *,
    port: int,
    protocols: list[str],
    addresses: list[str],
) -> list[dict[str, Any]]:
    _expect(isinstance(value, dict), "Why output was not an object")
    _expect(value.get("schema") == "kickoutchi.why" and value.get("version") == 1, "Why schema/version differed")
    query = value.get("query", {})
    _expect(query.get("port") == port, "Why query port differed")
    _expect(query.get("protocols") == protocols, "Why query protocol order differed")
    _expect(query.get("addresses") == addresses, "Why query address order differed")
    results = value.get("results")
    _expect(isinstance(results, list), "Why results was not an array")
    expected = [_endpoint(protocol, address, port) for protocol in protocols for address in addresses]
    actual = []
    for result in results:
        endpoint = result.get("endpoint", {})
        actual.append(_endpoint(endpoint.get("protocol"), endpoint.get("address"), endpoint.get("port")))
        _expect(result.get("verdict") in {
            "bindable_now", "owned", "owner_hidden", "kernel_state_observed",
            "permission_denied", "address_unavailable", "reservation_or_policy_unknown",
            "observation_raced", "unsupported", "indeterminate",
        }, "Why returned an unknown verdict")
        probe = result.get("probe", {})
        _expect(probe.get("outcome") in {
            "bindable_now", "address_in_use", "permission_denied", "address_unavailable",
            "unsupported", "other",
        }, "Why returned an unknown probe outcome")
    _expect(actual == expected, f"Why endpoints differed: {actual!r}")
    _expect(value.get("aggregate_exit_code") in {0, 1, 3, 4}, "Why aggregate exit code differed")
    return results


class FixedListener:
    def __init__(self, protocol: str, address: str, port: int):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        self.socket = socket.socket(family, kind)
        try:
            if family == socket.AF_INET6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.socket.bind((address, port))
            if protocol == "tcp":
                self.socket.listen(8)
        except BaseException:
            self.socket.close()
            raise
        self.protocol = protocol
        self.address = address
        self.port = self.socket.getsockname()[1]

    def close(self) -> None:
        self.socket.close()


def _find_matrix_port(ipv6: bool) -> int:
    for _ in range(64):
        probe = FixedListener("tcp", "127.0.0.1", 0)
        port = probe.port
        probe.close()
        listeners: list[FixedListener] = []
        try:
            for protocol in ("tcp", "udp"):
                for address in (["127.0.0.1", "::1"] if ipv6 else ["127.0.0.1"]):
                    listeners.append(FixedListener(protocol, address, port))
        except OSError:
            continue
        finally:
            for listener in listeners:
                listener.close()
        return port
    raise release_qa.HarnessError("could not reserve a collision-free matrix port")


def _ipv6_supported() -> bool:
    try:
        listener = FixedListener("tcp", "::1", 0)
    except OSError:
        return False
    listener.close()
    return True


class ControlledCommand:
    def __init__(self, command: Sequence[str], *, env: dict[str, str], cwd: Path, limit: int = 4 * 1024 * 1024):
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        self.process = subprocess.Popen(
            list(command), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=os.name == "posix", creationflags=flags,
        )
        assert self.process.stdout is not None and self.process.stderr is not None
        self.command = [str(item) for item in command]
        self.started = time.monotonic()
        self.captured: dict[str, Any] = {"stdout": bytearray(), "stderr": bytearray()}
        self.capture_lock = threading.Lock()
        self.limit = limit
        self.readers = [
            threading.Thread(target=self._read_live_bounded, args=(self.process.stdout, "stdout"), daemon=True),
            threading.Thread(target=self._read_live_bounded, args=(self.process.stderr, "stderr"), daemon=True),
        ]
        for reader in self.readers:
            reader.start()

    def _read_live_bounded(self, pipe: Any, key: str) -> None:
        try:
            while True:
                chunk = os.read(pipe.fileno(), 65_536)
                if not chunk:
                    return
                with self.capture_lock:
                    remaining = self.limit - len(self.captured[key])
                    self.captured[key].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        self.captured[f"{key}_truncated"] = True
                        pipe.close()
                        return
        except OSError as error:
            self.captured[f"{key}_read_error"] = str(error)
        finally:
            with contextlib.suppress(OSError):
                pipe.close()

    def stdout_text(self) -> str:
        with self.capture_lock:
            return bytes(self.captured["stdout"]).decode("utf-8", "replace")

    def wait_for_event(self, event: str, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in self.stdout_text().splitlines():
                with contextlib.suppress(json.JSONDecodeError):
                    if json.loads(line).get("event") == event:
                        return
            if self.process.poll() is not None:
                break
            time.sleep(0.01)
        raise release_qa.ProductFailure(f"watch did not emit {event} before its deadline")

    def interrupt(self) -> None:
        if self.process.poll() is not None:
            return
        if os.name == "posix":
            os.killpg(self.process.pid, signal.SIGINT)
        else:
            self.process.send_signal(signal.CTRL_BREAK_EVENT)

    def finish(self, timeout: float) -> dict[str, Any]:
        cleanup: list[str] = []
        timed_out = False
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            cleanup.extend(release_qa._terminate_process(self.process))
        for reader in self.readers:
            reader.join(timeout=release_qa.HELPER_STOP_TIMEOUT_SECONDS)
        if any(reader.is_alive() for reader in self.readers):
            cleanup.append("a controlled-command reader exceeded its join deadline")
        with self.capture_lock:
            stdout = bytes(self.captured["stdout"])
            stderr = bytes(self.captured["stderr"])
        return {
            "command": self.command, "pid": self.process.pid, "exit_code": self.process.returncode,
            "timed_out": timed_out, "duration_ms": round((time.monotonic() - self.started) * 1000, 3),
            "stdout": stdout.decode("utf-8", "replace"), "stderr": stderr.decode("utf-8", "replace"),
            "stdout_truncated": bool(self.captured.get("stdout_truncated")),
            "stderr_truncated": bool(self.captured.get("stderr_truncated")), "cleanup": cleanup,
        }


def _rss_bytes(pid: int) -> Optional[int]:
    if platform.system() == "Linux":
        try:
            for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            return None
    elif platform.system() == "Darwin":
        result = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip()) * 1024
    elif os.name == "nt":
        import ctypes
        import ctypes.wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", ctypes.wintypes.DWORD), ("PageFaultCount", ctypes.wintypes.DWORD)] + [(name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        handle = ctypes.windll.kernel32.OpenProcess(0x1000 | 0x0400, False, pid)
        if handle:
            try:
                counters = Counters(); counters.cb = ctypes.sizeof(counters)
                if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                    return int(counters.WorkingSetSize)
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
    return None


class Session:
    def __init__(self, candidate: Path, baseline: Path, root: Path, env: dict[str, str], timeout: float, report: dict[str, Any], privileged_watch: bool = False):
        self.candidate = str(candidate)
        self.baseline = str(baseline)
        self.root = root
        self.env = env
        self.timeout = timeout
        self.report = report
        self.privileged_watch = privileged_watch
        self.config = root / "empty.toml"
        self.config.write_text("", encoding="utf-8")
        self.owned_processes: list[subprocess.Popen[Any]] = []
        self.owned_sockets: list[FixedListener] = []
        self.controlled_commands: list[ControlledCommand] = []
        self.listener_metadata: dict[int, dict[str, Any]] = {}

    def command(self, args: Sequence[str], *, binary: Optional[str] = None, config: Optional[Path] = None, env: Optional[dict[str, str]] = None, add_config: bool = True) -> dict[str, Any]:
        command = [binary or self.candidate, *args]
        if add_config:
            command.extend(["--config", str(config or self.config)])
        return release_qa.run_command(command, env=env or self.env, cwd=self.root, timeout=self.timeout)

    def check(self, name: str, action: Callable[[], dict[str, Any]], capability: tuple[bool, str] = (True, "")) -> None:
        item: dict[str, Any] = {"name": name, "status": "INCONCLUSIVE", "evidence": {}}
        started = time.monotonic()
        if not capability[0]:
            item.update(status="BLOCKED", reason=capability[1])
        else:
            try:
                item["evidence"] = action()
                item["status"] = "PASS"
            except release_qa.ProductFailure as error:
                item.update(status="FAIL", reason=str(error))
            except Exception as error:
                item.update(status="INCONCLUSIVE", reason=f"harness could not establish the result: {error}", traceback=traceback.format_exc(limit=8))
        item["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
        self.report["checks"].append(item)

    def run(self) -> None:
        self.check("previous-release upgrade with absent and existing configuration", self.upgrade)
        self.check("bare and complete Why endpoint matrices", self.why_matrix)
        self.check("watch lifecycle, interruption, duration, and memory trend", self.watch_lifecycle)
        if platform.system() == "Linux":
            self.check("deterministic watch failure recovery and exhaustion", self.watch_failures, self._fault_capability())
        self.check("public input boundaries", self.boundaries)
        self.check("kill by port and protected refusal", self.kill_basics)
        self.check("safe tree termination", lambda: self.scoped_kill("tree"))
        if platform.system() in {"Linux", "Darwin"}:
            self.check("safe process-group termination", lambda: self.scoped_kill("group"))
        self.check("native platform scope and exclusions", self.platform_scope)
        if platform.system() == "Linux":
            self.check("permission-limited process metadata", self.permission_visibility)
            self.check("isolated user and network namespace", self.linux_namespace)
            self.check("Docker network namespace", self.linux_docker)

    def upgrade(self) -> dict[str, Any]:
        baseline_version = self.command(["--version"], binary=self.baseline, add_config=False)
        candidate_version = self.command(["--version"], add_config=False)
        release_qa._expect_exit(baseline_version, {0}); release_qa._expect_exit(candidate_version, {0})
        _expect(baseline_version["stdout"].startswith("kickoutchi 1.2."), "baseline artifact was not v1.2")
        _expect(candidate_version["stdout"].startswith("kickoutchi 1.3."), "candidate artifact was not v1.3")
        absent_old = self.command(["list", "--json"], binary=self.baseline, add_config=False)
        absent_new = self.command(["list", "--json"], add_config=False)
        _expect(isinstance(_result_json(absent_old, {0}), list), "v1.2 absent-config list was not an array")
        _expect(isinstance(_result_json(absent_new, {0}), list), "v1.3 absent-config list was not an array")
        config_dir = self.root / ("appdata/kickoutchi" if os.name == "nt" else ("home/Library/Application Support/kickoutchi" if platform.system() == "Darwin" else "config-home/kickoutchi"))
        config_dir.mkdir(parents=True, exist_ok=True)
        existing = config_dir / "config.toml"
        existing.write_text('refresh_interval_seconds = 7\ndefault_sort = "pid"\nhide_system_processes = false\nconfirm_force_kill = true\nprotected_processes = []\n', encoding="utf-8")
        old = self.command(["list", "--json"], binary=self.baseline, add_config=False)
        new = self.command(["list", "--json"], add_config=False)
        _expect(isinstance(_result_json(old, {0}), list), "v1.2 existing config failed")
        _expect(isinstance(_result_json(new, {0}), list), "v1.3 did not accept v1.2 config")
        _expect(existing.read_text(encoding="utf-8").startswith("refresh_interval_seconds = 7"), "upgrade modified the existing config")
        return {"versions": [baseline_version, candidate_version], "absent": [absent_old, absent_new], "existing": [old, new]}

    def why_matrix(self) -> dict[str, Any]:
        ipv6 = _ipv6_supported()
        port = _find_matrix_port(ipv6)
        bare = self.command(["why", str(port), "--json"])
        bare_results = validate_why_document(_result_json(bare, {0, 3}), port=port, protocols=["tcp"], addresses=["127.0.0.1", "::1"])
        _expect(bare_results[0]["probe"]["outcome"] == "bindable_now", "bare IPv4 endpoint was not bindable")
        addresses = ["127.0.0.1", "0.0.0.0", "::1", "::"]
        bindable = self.command(["why", str(port), "--all-protocols", "--all-addresses", "--json"])
        bindable_results = validate_why_document(_result_json(bindable, {0, 3}), port=port, protocols=["tcp", "udp"], addresses=addresses)
        for result in bindable_results:
            if ":" not in result["endpoint"]["address"] or ipv6:
                _expect(result["probe"]["outcome"] == "bindable_now", "supported free endpoint was not bindable")
        occupied = []
        occupied_addresses = ["127.0.0.1", "0.0.0.0", "::1", "::"] if ipv6 else ["127.0.0.1", "0.0.0.0"]
        for protocol in ("tcp", "udp"):
            for address in occupied_addresses:
                holder = FixedListener(protocol, address, 0)
                try:
                    occupied_result = self.command(["why", str(holder.port), f"--{protocol}", "--address", address, "--json"])
                    occupied_results = validate_why_document(_result_json(occupied_result, {3}), port=holder.port, protocols=[protocol], addresses=[address])
                    _expect(occupied_results[0]["probe"]["outcome"] == "address_in_use", "controlled occupied endpoint was not address-in-use")
                    occupied.append(occupied_result)
                finally:
                    holder.close()
        return {"ipv6_supported": ipv6, "bare": bare, "bindable": bindable, "occupied": occupied}

    def watch_lifecycle(self) -> dict[str, Any]:
        port = _find_matrix_port(False)
        listener = FixedListener("tcp", "127.0.0.1", port)
        self.owned_sockets.append(listener)
        command = [self.candidate, "watch", "--json", "--tcp", "--port", str(port), "--interval", "500ms", "--config", str(self.config)]
        if self.privileged_watch:
            command = ["sudo", "-n", *command]
        controlled = ControlledCommand(command, env=self.env, cwd=self.root)
        self.controlled_commands.append(controlled)
        try:
            controlled.wait_for_event("baseline", self.timeout)
        except release_qa.ProductFailure:
            result = controlled.finish(self.timeout)
            self.controlled_commands.remove(controlled)
            limitation = release_qa._macos_watch_limitation(result)
            if platform.system() == "Darwin" and limitation is not None:
                listener.close()
                self.owned_sockets.remove(listener)
                return {
                    "accepted_platform_limitation": limitation,
                    "outcome": "fail_closed_before_baseline",
                    "command": result,
                }
            raise
        listener.close(); self.owned_sockets.remove(listener)
        controlled.wait_for_event("release", self.timeout)
        replacement = FixedListener("tcp", "127.0.0.1", port); self.owned_sockets.append(replacement)
        controlled.wait_for_event("bind", self.timeout)
        replacement.close(); self.owned_sockets.remove(replacement)
        replacement_process = None
        replacement_limitation = None
        if platform.system() == "Linux":
            transient = FixedListener("tcp", "127.0.0.1", port)
            transient.close()
            replacement_process = self._start_fixed_listener_process("tcp", "127.0.0.1", port)
        else:
            replacement = FixedListener("tcp", "127.0.0.1", port); self.owned_sockets.append(replacement)
        try:
            controlled.wait_for_event("replacement", self.timeout)
        except release_qa.ProductFailure:
            if platform.system() != "Windows":
                raise
            snapshot = self.command(["list", "--snapshot-json"])
            snapshot_value = _result_json(snapshot, {0})
            _expect(snapshot_value.get("owner_completeness") == "partial", "Windows suppressed replacement without reporting partial ownership")
            replacement_limitation = {"reason": "incomplete_global_ownership_disables_replacement", "snapshot": snapshot}
        finally:
            if replacement_process is not None:
                release_qa._terminate_process(replacement_process)
                self.owned_processes.remove(replacement_process)
            for owned in list(self.owned_sockets):
                owned.close(); self.owned_sockets.remove(owned)
        controlled.interrupt()
        result = controlled.finish(self.timeout)
        self.controlled_commands.remove(controlled)
        release_qa._expect_exit(result, {0})
        records = release_qa.parse_ndjson(result["stdout"])
        events = [record.get("event") for record in records]
        expected_events = ("baseline", "release", "bind") if replacement_limitation else ("baseline", "release", "bind", "replacement")
        for expected in expected_events:
            _expect(expected in events, f"watch omitted {expected} event")
        duration = self.command(["watch", "--json", "--tcp", "--port", str(port), "--interval", "100ms", "--duration", "200ms"])
        release_qa._expect_exit(duration, {0})
        no_duration_command = [self.candidate, "watch", "--json", "--tcp", "--port", str(port), "--interval", "500ms", "--config", str(self.config)]
        no_duration = ControlledCommand(no_duration_command, env=self.env, cwd=self.root)
        self.controlled_commands.append(no_duration)
        samples = []
        for _ in range(MEMORY_SAMPLES):
            time.sleep(MEMORY_SAMPLE_SECONDS)
            sample = _rss_bytes(no_duration.process.pid)
            if sample is not None: samples.append(sample)
        _expect(no_duration.process.poll() is None, "no-duration watch exited before Ctrl-C")
        no_duration.interrupt(); interrupted = no_duration.finish(self.timeout)
        self.controlled_commands.remove(no_duration)
        release_qa._expect_exit(interrupted, {0})
        _expect(len(samples) >= MEMORY_SAMPLES // 2, "could not collect a finite memory trend")
        split = max(1, len(samples) // 4)
        _expect(max(samples[-split:]) <= max(samples[:split]) + MEMORY_GROWTH_LIMIT_BYTES, "finite no-duration watch memory trend exceeded 8 MiB")
        return {"lifecycle": result, "events": events, "replacement_limitation": replacement_limitation, "duration": duration, "interrupted": interrupted, "rss_bytes": samples, "growth_limit_bytes": MEMORY_GROWTH_LIMIT_BYTES}

    def _fault_capability(self) -> tuple[bool, str]:
        if platform.system() != "Linux":
            return False, "native Linux procfs fault injection only"
        if shutil.which("cc", path=self.env.get("PATH")) is None:
            return False, "a C compiler is required for the QA-owned procfs fault fixture"
        return True, ""

    def _fault_library(self) -> Path:
        output = self.root / "watch-fault.so"
        source = Path(__file__).with_name("watch_fault_fixture.c")
        result = release_qa.run_command(["cc", "-shared", "-fPIC", "-O2", "-o", str(output), str(source), "-ldl"], env=self.env, cwd=self.root, timeout=self.timeout)
        if result["exit_code"] != 0 or result["timed_out"]:
            raise release_qa.HarnessError("C compiler could not build the QA-owned fault fixture")
        return output

    def _fault_watch(self, plan: str, duration: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        state = self.root / f"fault-{plan.replace(',', '-')}.state"
        env = dict(self.env); env.update(LD_PRELOAD=str(self._fault_library()), KICKOUTCHI_QA_FAULT_STATE=str(state), KICKOUTCHI_QA_FAULT_PLAN=plan)
        result = self.command(["watch", "--json", "--interval", "100ms", "--duration", duration], env=env)
        records = release_qa.parse_ndjson(result["stdout"])
        try:
            result["collection_attempts"] = int(state.read_text(encoding="ascii"))
        except (OSError, ValueError) as error:
            raise release_qa.HarnessError(f"fault fixture state was unreadable: {error}") from error
        return result, records

    def watch_failures(self) -> dict[str, Any]:
        recovery, recovery_records = self._fault_watch("3", "400ms")
        release_qa._expect_exit(recovery, {0})
        recovery_events = [item.get("event") for item in recovery_records]
        _expect("collection_gap" in recovery_events, "transient failure emitted no collection gap")
        _expect(recovery["collection_attempts"] >= 3, "watch did not collect successfully after the transient failure")
        exhausted, exhausted_records = self._fault_watch("3,4,5", "5s")
        release_qa._expect_exit(exhausted, {1})
        gaps = [item for item in exhausted_records if item.get("event") == "collection_gap"]
        _expect(len(gaps) == 3, f"three-failure exhaustion emitted {len(gaps)} gaps")
        return {"fixture": "qa/watch_fault_fixture.c", "recovery": recovery, "recovery_events": recovery_events, "exhaustion": exhausted, "gap_count": len(gaps)}

    def boundaries(self) -> dict[str, Any]:
        maximum = self.root / "max.toml"; maximum.write_bytes(b"#" + b"x" * 65535)
        oversized = self.root / "oversized.toml"; oversized.write_bytes(b"#" + b"x" * 65536)
        invalid_utf8 = self.root / "invalid-utf8.toml"; invalid_utf8.write_bytes(b"\xff")
        unknown = self.root / "unknown.toml"; unknown.write_text("unknown = true\n", encoding="utf-8")
        cases = {
            "empty_config": (self.command(["list", "--json"]), {0}),
            "max_config": (self.command(["list", "--json"], config=maximum), {0}),
            "max_plus_one_config": (self.command(["list"], config=oversized), {1}),
            "invalid_utf8_config": (self.command(["list"], config=invalid_utf8), {1}),
            "unknown_config_key": (self.command(["list"], config=unknown), {1}),
            "empty_filter": (self.command(["list", "--json", "--filter", ""]), {0}),
            "malformed_filter": (self.command(["list", "--filter", "label:"]), {2}),
            "max_filter": (self.command(["list", "--filter", "x" * 256]), {3}),
            "max_plus_one_filter": (self.command(["list", "--filter", "x" * 257]), {2}),
            "why_zero_port": (self.command(["why", "0", "--json"]), {2}),
            "why_max_port": (self.command(["why", "65535", "--address", "127.0.0.1", "--json"]), {0, 3}),
            "why_max_plus_one_port": (self.command(["why", "65536", "--json"]), {2}),
            "why_zone_rejected": (self.command(["why", "1", "--address", "fe80::1%1", "--json"]), {2}),
            "watch_minimums": (self.command(["watch", "--json", "--interval", "100ms", "--duration", "100ms", "--filter", "port:65535"]), {0, 1} if platform.system() == "Darwin" else {0}),
            "watch_interval_below_min": (self.command(["watch", "--interval", "99ms", "--duration", "100ms"]), {2}),
            "watch_duration_below_min": (self.command(["watch", "--duration", "99ms"]), {2}),
        }
        for name, (result, exits) in cases.items():
            try: release_qa._expect_exit(result, exits)
            except release_qa.ProductFailure as error: raise release_qa.ProductFailure(f"{name}: {error}") from error
        if platform.system() == "Darwin" and cases["watch_minimums"][0]["exit_code"] == 1:
            _expect(release_qa._macos_watch_limitation(cases["watch_minimums"][0]) is not None, "minimum watch failed for an unrecognized reason")
        return {name: result for name, (result, _) in cases.items()}

    def _start_release_listener(self) -> tuple[release_qa.Listener, dict[str, Any]]:
        listener = release_qa.Listener(self.root, "tcp", "extended-qa", self.env)
        try:
            metadata = listener.start()
        except BaseException:
            listener.stop()
            raise
        return listener, metadata

    def kill_basics(self) -> dict[str, Any]:
        listener, metadata = self._start_release_listener()
        try:
            by_port = self.command(["kill", "--port", str(metadata["port"]), "--yes"])
            if platform.system() == "Darwin" and by_port["exit_code"] == 4:
                _expect(listener.process is not None and listener.process.poll() is None, "macOS partial-visibility refusal signalled the helper")
                return {"by_port": by_port, "accepted_platform_limitation": "process_first_socket_visibility_limited"}
            release_qa._expect_exit(by_port, {0})
            assert listener.process is not None
            listener.process.wait(timeout=release_qa.HELPER_STOP_TIMEOUT_SECONDS)
        finally: listener.stop()
        protected, protected_metadata = self._start_release_listener()
        protected_config = self.root / "protected.toml"
        observed = self.command(["list", "--json", "--port", str(protected_metadata["port"])])
        rows = _result_json(observed, {0})
        matching = [row for row in rows if row.get("pid") == protected_metadata["pid"]]
        _expect(len(matching) == 1 and isinstance(matching[0].get("process_name"), str), "could not resolve the helper's public process name")
        process_name = matching[0]["process_name"]
        protected_config.write_text(f'protected_processes = ["{process_name}"]\n', encoding="utf-8")
        try:
            refused = self.command(["kill", "--pid", str(protected_metadata["pid"]), "--yes"], config=protected_config)
            release_qa._expect_exit(refused, {6})
            _expect(protected.process is not None and protected.process.poll() is None, "protected refusal signalled the helper")
        finally: protected.stop()
        return {"by_port": by_port, "observed": observed, "protected": refused, "protected_process_name": process_name}

    def _tree_process(self) -> tuple[subprocess.Popen[Any], list[int]]:
        ready = self.root / f"tree-{time.monotonic_ns()}.json"
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        process = subprocess.Popen([sys.executable, "-m", "qa.extended_release_qa", "--_tree-helper", str(ready)], cwd=Path(__file__).resolve().parent.parent, env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=os.name == "posix", creationflags=flags)
        self.owned_processes.append(process)
        deadline = time.monotonic() + release_qa.HELPER_READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            with contextlib.suppress(OSError, json.JSONDecodeError):
                pids = json.loads(ready.read_text(encoding="utf-8"))["pids"]
                return process, pids
            time.sleep(0.01)
        raise release_qa.HarnessError("tree fixture missed readiness deadline")

    def _start_fixed_listener_process(self, protocol: str, address: str, port: int, *, restricted: bool = False) -> subprocess.Popen[Any]:
        ready = self.root / f"replacement-{time.monotonic_ns()}.json"
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        process = subprocess.Popen(
            [sys.executable, "-m", "qa.extended_release_qa", "--_listener-helper", protocol, address, str(port), str(ready), "restricted" if restricted else "normal"],
            cwd=Path(__file__).resolve().parent.parent,
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name == "posix",
            creationflags=flags,
        )
        self.owned_processes.append(process)
        deadline = time.monotonic() + release_qa.HELPER_READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise release_qa.HarnessError("replacement listener exited before readiness")
            with contextlib.suppress(OSError, json.JSONDecodeError):
                value = json.loads(ready.read_text(encoding="utf-8"))
                expected = (
                    value.get("pid") == process.pid
                    and value.get("protocol") == protocol
                    and value.get("address") == address
                    and value.get("restricted") is restricted
                    and isinstance(value.get("port"), int)
                    and value["port"] > 0
                    and (port == 0 or value["port"] == port)
                )
                if expected:
                    self.listener_metadata[process.pid] = value
                    return process
            time.sleep(0.01)
        raise release_qa.HarnessError("replacement listener missed its readiness deadline")

    def scoped_kill(self, scope: str) -> dict[str, Any]:
        process, pids = self._tree_process()
        result = self.command(["kill", "--pid", str(process.pid), f"--{scope}", "--yes"])
        release_qa._expect_exit(result, {0})
        try: process.wait(timeout=release_qa.HELPER_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error: raise release_qa.ProductFailure(f"{scope} root survived") from error
        self.owned_processes.remove(process)
        deadline = time.monotonic() + release_qa.HELPER_STOP_TIMEOUT_SECONDS
        while time.monotonic() < deadline and any(_pid_alive(pid) for pid in pids): time.sleep(0.01)
        _expect(not any(_pid_alive(pid) for pid in pids), f"{scope} left fixture descendants alive")
        return {"command": result, "fixture_pids": pids}

    def platform_scope(self) -> dict[str, Any]:
        result = self.command(["list", "--snapshot-json"])
        value = _result_json(result, {0})
        scope = value.get("scope", {})
        expected = {"Linux": ("current_network_namespace", "other_network_namespaces_excluded"), "Darwin": ("current_host_process_visible_sockets", "process_first_socket_visibility_limited"), "Windows": ("current_host_network_stack", "wsl_network_stack_excluded")}
        system = platform.system()
        _expect(system in expected, f"unsupported platform {system} did not fail closed")
        kind, limitation = expected[system]
        _expect(scope.get("kind") == kind, "native observation scope kind differed")
        _expect(limitation in scope.get("limitations", []), "native scope exclusion was not reported")
        if system == "Windows":
            _expect("wsl_network_stack_excluded" in scope["limitations"], "Windows did not report its WSL exclusion contract")
            wsl_status = release_qa.run_command(["wsl.exe", "--status"], env=self.env, cwd=self.root, timeout=self.timeout)
            wsl_distributions = release_qa.run_command(["wsl.exe", "--list", "--quiet"], env=self.env, cwd=self.root, timeout=self.timeout)
            _expect(not wsl_status["timed_out"] and not wsl_distributions["timed_out"], "WSL capability probe timed out")
            return {"command": result, "scope": scope, "wsl_execution_claimed": False, "wsl_status": wsl_status, "wsl_distributions": wsl_distributions}
        return {"command": result, "scope": scope, "wsl_execution_claimed": False}

    def permission_visibility(self) -> dict[str, Any]:
        listener = self._start_fixed_listener_process("tcp", "127.0.0.1", 0, restricted=True)
        metadata = self.listener_metadata[listener.pid]
        try:
            result = self.command(["list", "--snapshot-json"])
            value = _result_json(result, {0})
            rows = [row for row in value.get("sockets", []) if row.get("local_port") == metadata["port"]]
            gaps = [gap for gap in value.get("evidence_gaps", []) if gap.get("code") == "owner_permission_denied" and gap.get("pid") == metadata["pid"]]
            _expect(value.get("owner_completeness") == "partial", "permission denial did not mark ownership partial")
            _expect(not rows, "permission-limited listener incorrectly appeared as fully attributed")
            _expect(bool(gaps), "permission-limited listener emitted no PID-specific evidence gap")
            return {"command": result, "fixture": metadata, "owner_completeness": value.get("owner_completeness"), "matching_evidence_gaps": gaps}
        finally:
            release_qa._terminate_process(listener)
            self.owned_processes.remove(listener)

    def linux_namespace(self) -> dict[str, Any]:
        result = release_qa.run_command(
            ["unshare", "--user", "--map-root-user", "--net", "--pid", "--fork", "--mount-proc", self.candidate, "list", "--snapshot-json", "--config", str(self.config)],
            env=self.env,
            cwd=self.root,
            timeout=self.timeout,
        )
        if result["exit_code"] == 1 and "operation not permitted" in result["stderr"].lower():
            return {"unshare": result, "host_limit": "unprivileged_namespace_creation_denied", "docker_fallback": self.linux_docker()}
        value = _result_json(result, {0})
        _expect(value.get("scope", {}).get("kind") == "current_network_namespace", "isolated namespace scope differed")
        return {"command": result, "scope": value.get("scope"), "socket_count": len(value.get("sockets", []))}

    def linux_docker(self) -> dict[str, Any]:
        image = "ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
        name = f"kickoutchi-qa-{os.getpid()}-{time.monotonic_ns()}"
        command = [
            "docker", "run", "--rm", "--name", name, "--network", "none", "--read-only",
            "--mount", f"type=bind,src={self.candidate},dst=/candidate,readonly", image,
            "/candidate", "list", "--snapshot-json", "--config", "/dev/null",
        ]
        result = release_qa.run_command(command, env=self.env, cwd=self.root, timeout=self.timeout)
        cleanup = release_qa.run_command(["docker", "rm", "--force", name], env=self.env, cwd=self.root, timeout=self.timeout)
        if cleanup["exit_code"] not in {0, 1} or cleanup["timed_out"]:
            raise release_qa.HarnessError("Docker fixture cleanup was not conclusive")
        value = _result_json(result, {0})
        _expect(value.get("scope", {}).get("kind") == "current_network_namespace", "Docker namespace scope differed")
        return {"command": result, "cleanup": cleanup, "image": image, "scope": value.get("scope"), "socket_count": len(value.get("sockets", []))}

    def cleanup(self) -> list[str]:
        notes = []
        for command in self.controlled_commands:
            notes.extend(release_qa._terminate_process(command.process))
            result = command.finish(release_qa.HELPER_STOP_TIMEOUT_SECONDS)
            notes.extend(result["cleanup"])
        self.controlled_commands.clear()
        for listener in self.owned_sockets:
            with contextlib.suppress(OSError): listener.close()
            notes.append("closed harness-owned socket")
        self.owned_sockets.clear()
        for process in self.owned_processes:
            notes.extend(release_qa._terminate_process(process))
        self.owned_processes.clear()
        return notes


def _pid_alive(pid: int) -> bool:
    if os.name == "posix":
        try: os.kill(pid, 0)
        except ProcessLookupError: return False
        except PermissionError: return True
        try:
            fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
            return len(fields) < 3 or fields[2] != "Z"
        except OSError: return True
    result = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=2)
    return result.returncode == 0 and str(pid) in result.stdout


def _tree_helper(ready: Path) -> int:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
    descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"pids": [os.getpid(), child.pid]}, stream); stream.flush(); os.fsync(stream.fileno())
    try: child.wait()
    finally:
        if child.poll() is None: child.kill(); child.wait()
    return 0


def _listener_helper(protocol: str, address: str, port: int, ready: Path, restricted: bool) -> int:
    if restricted:
        if platform.system() != "Linux" or ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "could not make listener process nondumpable")
    listener = FixedListener(protocol, address, port)
    descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"pid": os.getpid(), "protocol": protocol, "address": address, "port": listener.port, "restricted": restricted}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        signal.pause() if os.name == "posix" else time.sleep(300)
    finally:
        listener.close()
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    candidate_info = release_qa.validate_binary(args.candidate.resolve())
    baseline_info = release_qa.validate_binary(args.baseline.resolve())
    if candidate_info["sha256"] != args.candidate_sha256 or baseline_info["sha256"] != args.baseline_sha256:
        raise release_qa.HarnessError("an executable SHA-256 did not match its explicit artifact identity")
    descriptor = release_qa.reserve_output(args.output)
    report: dict[str, Any] = {
        "report": "kickoutchi.extended_release_qa", "version": REPORT_VERSION,
        "overall": "INCONCLUSIVE", "candidate_commit": args.candidate_commit,
        "artifacts": {"candidate": candidate_info, "baseline": baseline_info},
        "context": release_qa._context([candidate_info, baseline_info]), "checks": [], "cleanup": [],
        "authorization": {"target": "exact local artifacts and QA-owned files, sockets, process trees, and groups", "bounded": True},
    }
    try:
        with tempfile.TemporaryDirectory(prefix="kickoutchi-extended-qa-") as temporary:
            root = Path(temporary); env = release_qa._isolated_environment(root)
            session = Session(args.candidate.resolve(), args.baseline.resolve(), root, env, args.timeout, report, args.privileged_watch)
            try: session.run()
            finally:
                report["cleanup"] = session.cleanup()
                if not release_qa._cleanup_proven(report["cleanup"]):
                    report["checks"].append({"name": "fail-closed cleanup", "status": "INCONCLUSIVE", "reason": "an owned process could not be proven reaped", "evidence": {"cleanup": report["cleanup"]}})
        report["temporary_tree_removed"] = not root.exists()
        if not report["temporary_tree_removed"]:
            report["checks"].append({"name": "fail-closed cleanup", "status": "INCONCLUSIVE", "reason": "temporary tree remained", "evidence": {}})
    except Exception as error:
        report["checks"].append({"name": "harness lifecycle", "status": "INCONCLUSIVE", "reason": str(error), "traceback": traceback.format_exc(limit=8), "evidence": {}})
    report["overall"] = release_qa._overall(report["checks"])
    release_qa._write_report(descriptor, report)
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--_tree-helper":
        raise SystemExit(_tree_helper(Path(sys.argv[2])))
    if len(sys.argv) == 7 and sys.argv[1] == "--_listener-helper":
        raise SystemExit(_listener_helper(sys.argv[2], sys.argv[3], int(sys.argv[4]), Path(sys.argv[5]), sys.argv[6] == "restricted"))
    raise SystemExit(main())
