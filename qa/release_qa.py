#!/usr/bin/env python3
"""Bounded exploratory QA for two extracted Kickoutchi release binaries."""

import argparse
import contextlib
import hashlib
import json
import locale
import os
import platform
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence


BINARY_MAX_BYTES = 512 * 1024 * 1024
COMMAND_OUTPUT_MAX_BYTES = 32 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 15.0
WATCH_TIMEOUT_SECONDS = 20.0
HELPER_READY_TIMEOUT_SECONDS = 5.0
HELPER_STOP_TIMEOUT_SECONDS = 3.0
PTY_OUTPUT_MAX_BYTES = 256 * 1024
NDJSON_RECORD_MAX_BYTES = 64 * 1024
NDJSON_RECORDS_MAX = 4096
CONFIG_MAX_BYTES = 65_536
FILTER_MAX_BYTES = 256
REPORT_VERSION = 1
STATUSES = frozenset({"PASS", "FAIL", "BLOCKED", "INCONCLUSIVE"})


class HarnessError(Exception):
    """A bounded harness operation could not produce reliable evidence."""


class ProductFailure(Exception):
    """Observed release behavior violated an acceptance contract."""


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not 0.05 <= parsed <= 300.0:
        raise argparse.ArgumentTypeError("must be in 0.05..=300 seconds")
    return parsed


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run bounded exploratory QA against extracted release binaries."
    )
    parser.add_argument("--canonical", required=True, type=Path)
    parser.add_argument("--short", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--windows-tui-evidence", type=Path)
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=COMMAND_TIMEOUT_SECONDS,
        help="per-command timeout in seconds (default: %(default)s)",
    )
    parsed = parser.parse_args(argv)
    for name, value, length in (
        ("candidate commit", parsed.candidate_commit, 40),
        ("archive SHA-256", parsed.archive_sha256, 64),
    ):
        if len(value) != length or any(character not in "0123456789abcdef" for character in value):
            parser.error(f"{name} must be {length} lowercase hexadecimal characters")
    return parsed


def read_windows_tui_evidence(path: Path, binary_sha256: str) -> dict[str, Any]:
    if os.name != "nt":
        raise HarnessError("Windows TUI evidence is valid only on Windows")
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
            raise HarnessError("Windows TUI evidence must be a bounded regular non-link file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessError(f"Windows TUI evidence is unreadable: {error}") from error
    required = {
        "schema": "kickoutchi.windows_tui_smoke",
        "version": 1,
        "status": "PASS",
        "mechanism": "winpty",
        "binary_sha256": binary_sha256,
        "exit_code": 0,
        "timed_out": False,
        "output_oversized": False,
        "entered_alternate_screen": True,
        "left_alternate_screen": True,
    }
    if not isinstance(value, dict) or any(value.get(key) != expected for key, expected in required.items()):
        raise HarnessError("Windows TUI evidence does not prove the required console lifecycle")
    return value


def validate_binary(path: Path, *, max_bytes: int = BINARY_MAX_BYTES) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        path_info = path.lstat()
        if stat.S_ISLNK(path_info.st_mode):
            raise HarnessError(f"binary {path} must not be a symbolic link")
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HarnessError(f"binary {path} is unavailable: {error}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise HarnessError(f"binary {path} is not a regular file")
        if info.st_size <= 0:
            raise HarnessError(f"binary {path} is empty")
        if info.st_size > max_bytes:
            raise HarnessError(
                f"binary {path} is {info.st_size} bytes; limit is {max_bytes}"
            )
        if os.name != "nt" and info.st_mode & 0o111 == 0:
            raise HarnessError(f"binary {path} is not executable")
        digest = hashlib.sha256()
        read_bytes = 0
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            while read_bytes <= max_bytes:
                chunk = stream.read(min(1024 * 1024, max_bytes + 1 - read_bytes))
                if not chunk:
                    break
                digest.update(chunk)
                read_bytes += len(chunk)
        after = os.fstat(descriptor)
        if read_bytes != info.st_size or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise HarnessError(f"binary {path} changed while it was hashed")
        return {
            "path": str(path.resolve()),
            "size_bytes": info.st_size,
            "sha256": digest.hexdigest(),
        }
    except OSError as error:
        raise HarnessError(f"binary {path} could not be hashed: {error}") from error
    finally:
        os.close(descriptor)


def reserve_output(path: Path) -> int:
    if not path.parent.is_dir():
        raise HarnessError(f"output parent is not a directory: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    try:
        return os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise HarnessError(f"refusing to overwrite existing output: {path}") from error
    except OSError as error:
        raise HarnessError(f"cannot reserve output {path}: {error}") from error


def _read_pipe_bounded(
    pipe: Any, limit: int, result: dict[str, Any], key: str
) -> None:
    data = bytearray()
    truncated = False
    try:
        while len(data) <= limit:
            chunk = pipe.read(min(65_536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            del data[limit:]
            truncated = True
            pipe.close()
    except OSError as error:
        result[f"{key}_read_error"] = str(error)
    finally:
        with contextlib.suppress(OSError):
            pipe.close()
    result[key] = bytes(data)
    result[f"{key}_truncated"] = truncated


def _terminate_process(process: subprocess.Popen[bytes]) -> list[str]:
    notes: list[str] = []
    if process.poll() is not None:
        return notes
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
            notes.append("sent SIGKILL to harness-owned process group")
        else:
            process.kill()
            notes.append("called kill on harness-owned process")
    except (OSError, ProcessLookupError) as error:
        notes.append(f"termination error: {error}")
    try:
        process.wait(timeout=HELPER_STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        notes.append("process did not reap before cleanup deadline")
    return notes


def run_command(
    command: Sequence[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout: float,
    output_limit: int = COMMAND_OUTPUT_MAX_BYTES,
    stdin: Optional[bytes] = None,
) -> dict[str, Any]:
    started = time.monotonic()
    creationflags = 0
    if os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
            creationflags=creationflags,
        )
    except OSError as error:
        raise HarnessError(f"could not start {command[0]}: {error}") from error
    assert process.stdout is not None and process.stderr is not None
    captured: dict[str, Any] = {}
    readers = [
        threading.Thread(
            target=_read_pipe_bounded,
            args=(process.stdout, output_limit, captured, "stdout"),
            daemon=True,
        ),
        threading.Thread(
            target=_read_pipe_bounded,
            args=(process.stderr, output_limit, captured, "stderr"),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    if stdin is not None and process.stdin is not None:
        try:
            process.stdin.write(stdin)
            process.stdin.close()
        except OSError as error:
            captured["stdin_write_error"] = str(error)
    timed_out = False
    cleanup: list[str] = []
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        cleanup.extend(_terminate_process(process))
    for reader in readers:
        reader.join(timeout=HELPER_STOP_TIMEOUT_SECONDS)
    if any(reader.is_alive() for reader in readers):
        cleanup.append("a pipe reader exceeded its join deadline")
    stdout = captured.get("stdout", b"")
    stderr = captured.get("stderr", b"")
    return {
        "command": [str(part) for part in command],
        "cwd": str(cwd),
        "pid": process.pid,
        "process_group_owned": os.name == "posix",
        "timeout_seconds": timeout,
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "stdout": stdout.decode("utf-8", "replace"),
        "stderr": stderr.decode("utf-8", "replace"),
        "stdout_bytes_captured": len(stdout),
        "stderr_bytes_captured": len(stderr),
        "stdout_truncated": bool(captured.get("stdout_truncated")),
        "stderr_truncated": bool(captured.get("stderr_truncated")),
        "stdout_read_error": captured.get("stdout_read_error"),
        "stderr_read_error": captured.get("stderr_read_error"),
        "stdin_write_error": captured.get("stdin_write_error"),
        "cleanup": cleanup,
    }


def run_early_close(
    command: Sequence[str], *, env: dict[str, str], cwd: Path, timeout: float
) -> dict[str, Any]:
    creationflags = 0
    if os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    started = time.monotonic()
    process = subprocess.Popen(
        list(command),
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
        creationflags=creationflags,
    )
    assert process.stdout is not None and process.stderr is not None
    stdout_pipe = process.stdout
    first_byte_result: dict[str, Any] = {}
    first_byte_ready = threading.Event()

    def read_first_byte() -> None:
        try:
            first_byte_result["value"] = stdout_pipe.read(1)
        except OSError as error:
            first_byte_result["value"] = error
        finally:
            first_byte_ready.set()

    stderr_result: dict[str, Any] = {}
    stdout_reader = threading.Thread(target=read_first_byte, daemon=True)
    stderr_reader = threading.Thread(
        target=_read_pipe_bounded,
        args=(process.stderr, COMMAND_OUTPUT_MAX_BYTES, stderr_result, "stderr"),
        daemon=True,
    )
    stdout_reader.start()
    stderr_reader.start()
    cleanup: list[str] = []
    timed_out = False
    deadline = time.monotonic() + timeout
    if first_byte_ready.wait(timeout=max(0.0, deadline - time.monotonic())):
        first_value = first_byte_result.get("value", b"")
    else:
        first_value = b""
        timed_out = True
        cleanup.append("producer emitted no byte before its deadline")
        cleanup.extend(_terminate_process(process))
    if isinstance(first_value, OSError):
        first_byte = b""
        cleanup.append(f"first-byte read failed: {first_value}")
    else:
        first_byte = first_value
    with contextlib.suppress(OSError):
        stdout_pipe.close()
    try:
        if process.poll() is None:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        timed_out = True
        cleanup.extend(_terminate_process(process))
    stdout_reader.join(timeout=HELPER_STOP_TIMEOUT_SECONDS)
    stderr_reader.join(timeout=HELPER_STOP_TIMEOUT_SECONDS)
    if stdout_reader.is_alive() or stderr_reader.is_alive():
        cleanup.append("an early-close pipe reader exceeded its join deadline")
    stderr = stderr_result.get("stderr", b"")
    return {
        "command": [str(part) for part in command],
        "cwd": str(cwd),
        "pid": process.pid,
        "process_group_owned": os.name == "posix",
        "timeout_seconds": timeout,
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "first_stdout_byte_hex": first_byte.hex(),
        "stderr": stderr.decode("utf-8", "replace"),
        "stderr_bytes_captured": len(stderr),
        "stderr_truncated": bool(stderr_result.get("stderr_truncated")),
        "cleanup": cleanup,
    }


def parse_json_document(result: dict[str, Any]) -> Any:
    if result["timed_out"]:
        raise ProductFailure("command timed out")
    if result["stdout_truncated"] or result["stderr_truncated"]:
        raise ProductFailure("command output exceeded the harness bound")
    try:
        return json.loads(result["stdout"])
    except (TypeError, json.JSONDecodeError) as error:
        raise ProductFailure(f"stdout was not one JSON document: {error}") from error


def parse_ndjson(
    text: str,
    *,
    record_max_bytes: int = NDJSON_RECORD_MAX_BYTES,
    records_max: int = NDJSON_RECORDS_MAX,
) -> list[Any]:
    raw = text.encode("utf-8")
    lines = raw.splitlines(keepends=True)
    if len(lines) > records_max:
        raise HarnessError(f"NDJSON exceeded {records_max} records")
    records: list[Any] = []
    for index, line in enumerate(lines):
        if len(line) > record_max_bytes:
            raise HarnessError(f"NDJSON record {index} exceeded {record_max_bytes} bytes")
        if not line.endswith(b"\n"):
            raise HarnessError(f"NDJSON record {index} did not end with a newline")
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise HarnessError(f"NDJSON record {index} was invalid: {error}") from error
    return records


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise ProductFailure(message)


def _expect_exit(result: dict[str, Any], accepted: Iterable[int]) -> None:
    accepted_set = set(accepted)
    _expect(not result["timed_out"], "command timed out")
    _expect(result["exit_code"] in accepted_set, f"exit code was {result['exit_code']}, expected {sorted(accepted_set)}")
    _expect(not result["stdout_truncated"], "stdout exceeded the harness bound")
    _expect(not result["stderr_truncated"], "stderr exceeded the harness bound")


def _helper_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--_qa-helper", action="store_true")
    parser.add_argument("--ready", required=True, type=Path)
    parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    parser.add_argument("--marker", required=True)
    args = parser.parse_args(argv)
    sock_type = socket.SOCK_STREAM if args.protocol == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, sock_type) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        if args.protocol == "tcp":
            listener.listen(8)
        payload = {
            "pid": os.getpid(),
            "protocol": args.protocol,
            "address": "127.0.0.1",
            "port": listener.getsockname()[1],
        }
        descriptor = os.open(args.ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        stop = threading.Event()

        def request_stop(_signum: int, _frame: Any) -> None:
            stop.set()

        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, request_stop)
        if hasattr(signal, "SIGINT"):
            signal.signal(signal.SIGINT, request_stop)
        while not stop.wait(0.25):
            pass
    return 0


class Listener:
    def __init__(self, root: Path, protocol: str, marker: str, env: dict[str, str]):
        self.root = root
        self.protocol = protocol
        self.marker = marker
        self.env = env
        self.process: Optional[subprocess.Popen[bytes]] = None
        self.ready = root / f"listener-{protocol}-{uuid.uuid4().hex}.json"
        self.metadata: dict[str, Any] = {}
        self.cleanup: list[str] = []

    def start(self) -> dict[str, Any]:
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--_qa-helper",
            "--ready",
            str(self.ready),
            "--protocol",
            self.protocol,
            "--marker",
            self.marker,
        ]
        creationflags = 0
        if os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        self.process = subprocess.Popen(
            command,
            cwd=self.root,
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name == "posix",
            creationflags=creationflags,
        )
        deadline = time.monotonic() + HELPER_READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise HarnessError(f"{self.protocol} listener exited before readiness")
            try:
                if self.ready.stat().st_size > 0:
                    self.metadata = json.loads(self.ready.read_text(encoding="utf-8"))
                    break
            except (FileNotFoundError, OSError, json.JSONDecodeError):
                pass
            time.sleep(0.01)
        else:
            raise HarnessError(f"{self.protocol} listener missed its readiness deadline")
        self.metadata.update(
            {
                "role": "test-owned socket listener",
                "owned_by_harness": True,
                "process_group_owned": os.name == "posix",
                "marker_sha256": hashlib.sha256(self.marker.encode()).hexdigest(),
                "command": command,
            }
        )
        return dict(self.metadata)

    def stop(self) -> list[str]:
        process = self.process
        if process is None:
            return self.cleanup
        if process.poll() is None:
            try:
                if os.name == "posix":
                    os.kill(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
                process.wait(timeout=HELPER_STOP_TIMEOUT_SECONDS)
                self.cleanup.append("listener stopped and reaped")
            except (OSError, subprocess.TimeoutExpired) as error:
                self.cleanup.append(f"graceful stop failed: {error}")
                self.cleanup.extend(_terminate_process(process))
        else:
            self.cleanup.append(f"listener already exited with {process.returncode}")
        self.process = None
        return self.cleanup


class QaSession:
    def __init__(
        self,
        canonical: Path,
        short: Path,
        root: Path,
        env: dict[str, str],
        timeout: float,
        report: dict[str, Any],
        windows_tui_evidence: Optional[dict[str, Any]],
    ):
        self.canonical = str(canonical.resolve())
        self.short = str(short.resolve())
        self.root = root
        self.env = env
        self.timeout = timeout
        self.report = report
        self.windows_tui_evidence = windows_tui_evidence
        self.config_empty = root / "empty.toml"
        self.config_labels = root / "labels.toml"
        self.listeners: list[Listener] = []
        self.tcp: dict[str, Any] = {}
        self.udp: dict[str, Any] = {}
        self.marker = f"KICKOUTCHI_QA_SECRET_{uuid.uuid4().hex}"
        self.exact_label = f"qa-exact-{uuid.uuid4().hex[:10]}"
        self.wild_label = f"qa-wild-{uuid.uuid4().hex[:10]}"
        self._current_commands: Optional[list[dict[str, Any]]] = None

    def command(
        self,
        args: Sequence[str],
        *,
        binary: Optional[str] = None,
        timeout: Optional[float] = None,
        config: Optional[Path] = None,
    ) -> dict[str, Any]:
        selected_config = config or self.config_empty
        command = [binary or self.canonical, *args, "--config", str(selected_config)]
        result = run_command(
            command,
            env=self.env,
            cwd=self.root,
            timeout=timeout or self.timeout,
        )
        if self._current_commands is not None:
            self._current_commands.append(result)
        return result

    def record_result(self, result: dict[str, Any]) -> dict[str, Any]:
        if self._current_commands is not None:
            self._current_commands.append(result)
        return result

    def check(
        self,
        name: str,
        action: Callable[[], dict[str, Any]],
        *,
        capability: Optional[tuple[bool, str]] = None,
    ) -> None:
        started = time.monotonic()
        item: dict[str, Any] = {"name": name, "evidence": {}}
        if capability is not None and not capability[0]:
            item.update(
                {
                    "status": "BLOCKED",
                    "reason": capability[1],
                    "duration_ms": 0.0,
                    "evidence": {"missing_capability": capability[1]},
                }
            )
            self.report["checks"].append(item)
            return
        retained_commands: list[dict[str, Any]] = []
        self._current_commands = retained_commands
        try:
            item["evidence"] = action()
            item["status"] = "PASS"
        except ProductFailure as error:
            item["status"] = "FAIL"
            item["reason"] = str(error)
        except Exception as error:
            item["status"] = "INCONCLUSIVE"
            item["reason"] = f"harness could not establish the result: {error}"
            item["traceback"] = traceback.format_exc(limit=8)
        finally:
            self._current_commands = None
        if item["status"] != "PASS":
            item["evidence"] = {"commands_completed": retained_commands}
        item["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
        self.report["checks"].append(item)
        if item["status"] == "FAIL" and self.report["first_failure"] is None:
            self.report["first_failure"] = {
                "check": name,
                "reason": item.get("reason", "product acceptance failure"),
            }
        elif item["status"] in {"BLOCKED", "INCONCLUSIVE"} and self.report["first_failure"] is None:
            self.report["first_failure"] = {
                "check": name,
                "reason": item.get("reason", "evidence was not conclusive"),
            }

    def setup(self) -> None:
        self.config_empty.write_text("", encoding="utf-8")
        for protocol in ("tcp", "udp"):
            listener = Listener(self.root, protocol, self.marker, self.env)
            self.listeners.append(listener)
            metadata = listener.start()
            if protocol == "tcp":
                self.tcp = metadata
            else:
                self.udp = metadata
        config = (
            "[[ports]]\n"
            'protocol = "tcp"\n'
            'address = "127.0.0.1"\n'
            f"port = {self.tcp['port']}\n"
            f'label = "{self.exact_label}"\n\n'
            "[[ports]]\n"
            'protocol = "udp"\n'
            'address = "*"\n'
            f"port = {self.udp['port']}\n"
            f'label = "{self.wild_label}"\n'
        )
        self.config_labels.write_text(config, encoding="utf-8")
        self.report["helpers"] = [self.tcp, self.udp]

    def cleanup(self) -> None:
        for listener in reversed(self.listeners):
            listener.stop()
        for helper, listener in zip(self.report.get("helpers", []), self.listeners):
            helper["cleanup"] = list(listener.cleanup)
        self.report["cleanup"] = [
            {
                "pid": listener.metadata.get("pid"),
                "protocol": listener.protocol,
                "result": list(listener.cleanup),
            }
            for listener in self.listeners
        ]

    def run(self) -> None:
        self.check("canonical and short version parity", self._version_parity)
        self.check("no-label table and legacy JSON array", self._no_label_outputs)
        self.check("exact and wildcard labels in list and search", self._label_list_search)
        self.check("snapshot schema, labels, and privacy", self._snapshot)
        self.check("why schema, labels, and privacy", self._why)
        self.check("watch duration, baseline NDJSON, labels, and privacy", self._watch)
        self.check("short binary functional parity", self._short_parity)
        self.check("configuration and filter boundaries", self._boundaries)
        self.check("early-closing JSON and NDJSON consumers", self._early_close)
        self.check("read-only inspect", self._inspect)
        self.check("safe test-owned kill", self._safe_kill, capability=self._kill_capability())
        if os.name == "posix":
            self.check("TUI PTY smoke", self._tui)
        else:
            self.check(
                "TUI pseudo-console smoke",
                lambda: dict(self.windows_tui_evidence or {}),
                capability=(self.windows_tui_evidence is not None, "validated WinPTY console evidence was not supplied"),
            )

    def _version_parity(self) -> dict[str, Any]:
        canonical = self.command(["--version"])
        short = self.command(["--version"], binary=self.short)
        _expect_exit(canonical, {0})
        _expect_exit(short, {0})
        _expect(canonical["stdout"] == short["stdout"], "binary versions differ")
        _expect(canonical["stdout"].startswith("kickoutchi "), "version did not use canonical name")
        return {"canonical": canonical, "short": short}

    def _no_label_outputs(self) -> dict[str, Any]:
        table = self.command(["list"])
        legacy = self.command(["list", "--json"])
        _expect_exit(table, {0})
        _expect_exit(legacy, {0})
        value = parse_json_document(legacy)
        _expect(isinstance(value, list), "legacy JSON top level was not an array")
        _expect("LABEL" not in table["stdout"], "table showed LABEL with empty config")
        _expect(self.marker not in table["stdout"], "table leaked the fixture command marker")
        marker_rows = [row for row in value if self.marker in str(row.get("command_line"))]
        _expect(bool(marker_rows), "legacy output did not expose the fixture command line as documented")
        return {
            "table": table,
            "legacy": legacy,
            "legacy_shape": "array",
            "legacy_marker_rows": len(marker_rows),
            "privacy_note": "legacy command_line exposure is the documented compatibility exception",
        }

    def _label_list_search(self) -> dict[str, Any]:
        all_rows_result = self.command(["list", "--json"], config=self.config_labels)
        plain = self.command(
            ["list", "--json", "--filter", self.exact_label], config=self.config_labels
        )
        filtered = self.command(
            ["list", "--json", "--filter", f"label:{self.wild_label}"], config=self.config_labels
        )
        for result in (all_rows_result, plain, filtered):
            _expect_exit(result, {0})
        all_rows = parse_json_document(all_rows_result)
        plain_rows = parse_json_document(plain)
        filtered_rows = parse_json_document(filtered)
        by_port = {row.get("local_port"): row for row in all_rows}
        _expect(by_port.get(self.tcp["port"], {}).get("label") == self.exact_label, "exact label did not resolve")
        _expect(by_port.get(self.udp["port"], {}).get("label") == self.wild_label, "wildcard label did not resolve")
        _expect(plain_rows and all(row.get("label") == self.exact_label for row in plain_rows), "plain label search was not selective")
        _expect(filtered_rows and all(row.get("label") == self.wild_label for row in filtered_rows), "label filter was not selective")
        return {"all": all_rows_result, "plain_search": plain, "label_filter": filtered}

    def _snapshot(self) -> dict[str, Any]:
        result = self.command(["list", "--snapshot-json"], config=self.config_labels)
        _expect_exit(result, {0})
        value = parse_json_document(result)
        _expect(isinstance(value, dict), "snapshot top level was not an object")
        _expect(value.get("schema") == "kickoutchi.snapshot", "snapshot schema differed")
        _expect(value.get("version") == 1, "snapshot version differed")
        labels = {item.get("label") for item in value.get("sockets", [])}
        _expect({self.exact_label, self.wild_label} <= labels, "snapshot omitted fixture labels")
        _expect(self.marker not in result["stdout"], "snapshot leaked the full command marker")
        return {"command": result, "socket_count": len(value.get("sockets", []))}

    def _why(self) -> dict[str, Any]:
        results = []
        for fixture, label in ((self.tcp, self.exact_label), (self.udp, self.wild_label)):
            protocol_flag = "--tcp" if fixture["protocol"] == "tcp" else "--udp"
            result = self.command(
                [
                    "why",
                    str(fixture["port"]),
                    protocol_flag,
                    "--address",
                    "127.0.0.1",
                    "--json",
                ],
                config=self.config_labels,
            )
            _expect_exit(result, {3})
            value = parse_json_document(result)
            _expect(value.get("schema") == "kickoutchi.why", "why schema differed")
            _expect(value.get("version") == 1, "why version differed")
            _expect(any(item.get("label") == label for item in value.get("results", [])), f"why omitted {label}")
            _expect(self.marker not in result["stdout"], "why leaked the full command marker")
            results.append(result)
        return {"commands": results}

    def _watch(self) -> dict[str, Any]:
        result = self.command(
            [
                "watch",
                "--json",
                "--interval",
                "100ms",
                "--duration",
                "100ms",
                "--filter",
                "label:qa-",
            ],
            config=self.config_labels,
            timeout=max(self.timeout, WATCH_TIMEOUT_SECONDS),
        )
        _expect_exit(result, {0})
        try:
            records = parse_ndjson(result["stdout"])
        except HarnessError as error:
            raise ProductFailure(str(error)) from error
        _expect(bool(records), "watch emitted no baseline records")
        _expect(all(record.get("schema") == "kickoutchi.watch_event" for record in records), "watch schema differed")
        _expect(all(record.get("version") == 1 for record in records), "watch version differed")
        _expect(all(record.get("event") == "baseline" for record in records), "initial watch records were not baseline events")
        labels = {
            record.get("data", {}).get("label")
            for record in records
            if isinstance(record.get("data"), dict)
        }
        _expect({self.exact_label, self.wild_label} <= labels, "watch omitted fixture labels")
        _expect(self.marker not in result["stdout"], "watch leaked the full command marker")
        return {"command": result, "record_count": len(records), "events": sorted({record.get("event") for record in records})}

    def _short_parity(self) -> dict[str, Any]:
        args = ["list", "--json", "--filter", "label:qa-"]
        canonical = self.command(args, config=self.config_labels)
        short = self.command(args, binary=self.short, config=self.config_labels)
        _expect_exit(canonical, {0})
        _expect_exit(short, {0})
        first = parse_json_document(canonical)
        second = parse_json_document(short)
        fields = ("protocol", "local_addr", "local_port", "state", "pid", "label")
        project = lambda rows: sorted(tuple(row.get(field) for field in fields) for row in rows)
        _expect(project(first) == project(second), "short binary list projection differed")
        return {"canonical": canonical, "short": short, "compared_fields": list(fields)}

    def _boundaries(self) -> dict[str, Any]:
        malformed = self.root / "malformed.toml"
        maximum = self.root / "maximum.toml"
        too_large = self.root / "too-large.toml"
        malformed.write_text("this is not = toml\n", encoding="utf-8")
        prefix = b"#"
        maximum.write_bytes(prefix + b"x" * (CONFIG_MAX_BYTES - len(prefix)))
        too_large.write_bytes(prefix + b"x" * CONFIG_MAX_BYTES)
        commands = {
            "empty_config": self.command(["list", "--json"]),
            "malformed_config": self.command(["list"], config=malformed),
            "max_config": self.command(["list", "--json"], config=maximum),
            "max_plus_one_config": self.command(["list"], config=too_large),
            "empty_filter": self.command(["list", "--json", "--filter", ""]),
            "malformed_filter": self.command(["list", "--filter", "label:"]),
            "max_filter": self.command(["list", "--json", "--filter", "x" * FILTER_MAX_BYTES]),
            "max_plus_one_filter": self.command(["list", "--filter", "x" * (FILTER_MAX_BYTES + 1)]),
        }
        _expect_exit(commands["empty_config"], {0})
        _expect_exit(commands["malformed_config"], {1})
        _expect_exit(commands["max_config"], {0})
        _expect_exit(commands["max_plus_one_config"], {1})
        _expect_exit(commands["empty_filter"], {0})
        _expect_exit(commands["malformed_filter"], {2})
        _expect_exit(commands["max_filter"], {3})
        _expect_exit(commands["max_plus_one_filter"], {2})
        return commands

    def _early_close(self) -> dict[str, Any]:
        json_result = self.record_result(
            run_early_close(
                [
                    self.canonical,
                    "list",
                    "--snapshot-json",
                    "--config",
                    str(self.config_labels),
                ],
                env=self.env,
                cwd=self.root,
                timeout=self.timeout,
            )
        )
        watch_result = self.record_result(
            run_early_close(
                [
                    self.canonical,
                    "watch",
                    "--json",
                    "--duration",
                    "5s",
                    "--config",
                    str(self.config_labels),
                ],
                env=self.env,
                cwd=self.root,
                timeout=self.timeout,
            )
        )
        _expect(not json_result["timed_out"] and json_result["exit_code"] == 0, "early-closing JSON consumer was not successful")
        _expect(not watch_result["timed_out"] and watch_result["exit_code"] == 0, "early-closing NDJSON consumer was not successful")
        _expect(bool(json_result["first_stdout_byte_hex"]), "JSON producer emitted no byte")
        _expect(bool(watch_result["first_stdout_byte_hex"]), "NDJSON producer emitted no byte")
        return {"json": json_result, "ndjson": watch_result}

    def _inspect(self) -> dict[str, Any]:
        by_pid = self.command(["inspect", "--pid", str(self.tcp["pid"])], config=self.config_labels)
        by_port = self.command(["inspect", "--port", str(self.tcp["port"])], config=self.config_labels)
        _expect_exit(by_pid, {0})
        _expect_exit(by_port, {0})
        listener = next(item for item in self.listeners if item.protocol == "tcp")
        _expect(listener.process is not None and listener.process.poll() is None, "inspect signalled the test-owned listener")
        _expect(str(self.tcp["pid"]) in by_pid["stdout"], "inspect PID report omitted target PID")
        _expect(str(self.tcp["port"]) in by_port["stdout"], "inspect port report omitted target port")
        return {"by_pid": by_pid, "by_port": by_port}

    def _kill_capability(self) -> tuple[bool, str]:
        if platform.system() == "Linux":
            release = platform.release().split("-")[0].split(".")
            try:
                major, minor = int(release[0]), int(release[1])
            except (ValueError, IndexError):
                return False, "Linux kernel version could not be classified for pidfd support"
            if (major, minor) < (5, 3):
                return False, "Linux kernel is older than the documented pidfd termination requirement"
        return True, ""

    def _safe_kill(self) -> dict[str, Any]:
        owned = Listener(self.root, "tcp", self.marker, self.env)
        self.listeners.append(owned)
        metadata = owned.start()
        result = self.command(["kill", "--pid", str(metadata["pid"]), "--yes"])
        _expect_exit(result, {0})
        assert owned.process is not None
        try:
            owned.process.wait(timeout=HELPER_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise ProductFailure("kill returned success but test-owned process survived") from error
        _expect(owned.process.returncode is not None, "test-owned process was not reaped")
        return {"helper": metadata, "command": result, "helper_exit_code": owned.process.returncode}

    def _tui(self) -> dict[str, Any]:
        import errno
        import pty

        master, slave = pty.openpty()
        command = [self.canonical, "--config", str(self.config_labels)]
        tui_env = dict(self.env)
        tui_env["TERM"] = "xterm-256color"
        process = subprocess.Popen(
            command,
            cwd=self.root,
            env=tui_env,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            start_new_session=True,
        )
        os.close(slave)
        output = bytearray()
        truncated = False
        cleanup: list[str] = []
        selector: Optional[selectors.BaseSelector] = None
        try:
            ready_deadline = time.monotonic() + min(self.timeout, HELPER_READY_TIMEOUT_SECONDS)
            ready_selector = selectors.DefaultSelector()
            ready_selector.register(master, selectors.EVENT_READ)
            while time.monotonic() < ready_deadline and not output:
                if process.poll() is not None:
                    break
                if ready_selector.select(timeout=0.05):
                    chunk = os.read(master, min(65_536, PTY_OUTPUT_MAX_BYTES + 1))
                    output.extend(chunk)
            ready_selector.close()
            _expect(bool(output), "TUI produced no terminal output before its readiness deadline")
            os.write(master, b"q")
            deadline = time.monotonic() + self.timeout
            selector = selectors.DefaultSelector()
            selector.register(master, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                for _key, _mask in selector.select(timeout=0.05):
                    try:
                        chunk = os.read(master, min(65_536, PTY_OUTPUT_MAX_BYTES + 1 - len(output)))
                    except OSError as error:
                        if error.errno == errno.EIO:
                            chunk = b""
                        else:
                            raise
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > PTY_OUTPUT_MAX_BYTES:
                        del output[PTY_OUTPUT_MAX_BYTES:]
                        truncated = True
                if truncated:
                    break
            if process.poll() is None:
                cleanup.extend(_terminate_process(process))
                raise ProductFailure("TUI did not exit after q before its deadline")
            _expect(process.returncode == 0, f"TUI exited with {process.returncode}")
            _expect(bool(output), "TUI produced no terminal output")
            _expect(not truncated, "TUI output exceeded the harness bound")
        finally:
            if selector is not None:
                selector.close()
            with contextlib.suppress(OSError):
                os.close(master)
            if process.poll() is None:
                cleanup.extend(_terminate_process(process))
        return {
            "command": command,
            "pid": process.pid,
            "exit_code": process.returncode,
            "pty": "stdlib pty.openpty",
            "output_bytes_captured": len(output),
            "output_truncated": truncated,
            "output": output.decode("utf-8", "replace"),
            "cleanup": cleanup,
        }


def _isolated_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    config = root / "config-home"
    temp = root / "temp"
    appdata = root / "appdata"
    for directory in (home, config, temp, appdata):
        directory.mkdir()
    env = dict(os.environ)
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(config),
            "APPDATA": str(appdata),
            "LOCALAPPDATA": str(appdata),
            "TMPDIR": str(temp),
            "TMP": str(temp),
            "TEMP": str(temp),
            "NO_COLOR": "1",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    for name in tuple(env):
        if name.startswith("KICKOUTCHI_"):
            del env[name]
    return env


def _context(binary_info: list[dict[str, Any]]) -> dict[str, Any]:
    uname = platform.uname()
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "kernel": {"system": uname.system, "release": uname.release, "version": uname.version},
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "byteorder": sys.byteorder,
            "filesystem_encoding": sys.getfilesystemencoding(),
        },
        "tool": {
            "name": "qa/release_qa.py",
            "report_version": REPORT_VERSION,
            "standard_library_only": True,
            "argv": sys.argv,
        },
        "locale": {
            "preferred_encoding": locale.getpreferredencoding(False),
            "default": locale.setlocale(locale.LC_ALL, None),
        },
        "user": {
            "uid": os.getuid() if hasattr(os, "getuid") else None,
            "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        },
        "terminal": {"stdin_tty": sys.stdin.isatty(), "stdout_tty": sys.stdout.isatty()},
        "binaries": binary_info,
        "bounds": {
            "binary_bytes": BINARY_MAX_BYTES,
            "command_stream_bytes": COMMAND_OUTPUT_MAX_BYTES,
            "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
            "ndjson_record_bytes": NDJSON_RECORD_MAX_BYTES,
            "ndjson_records": NDJSON_RECORDS_MAX,
            "pty_output_bytes": PTY_OUTPUT_MAX_BYTES,
        },
    }


def _git_context() -> dict[str, Any]:
    commands = {
        "commit": ["git", "rev-parse", "HEAD"],
        "status": ["git", "status", "--porcelain=v1", "--untracked-files=all"],
    }
    values: dict[str, str] = {}
    for name, command in commands.items():
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            values[name] = f"unavailable: {error}"
        else:
            values[name] = result.stdout.strip()
    return {
        "harness_commit": values["commit"],
        "worktree_clean": values["status"] == "",
        "status": values["status"],
    }


def _overall(checks: Sequence[dict[str, Any]]) -> str:
    statuses = {check.get("status") for check in checks}
    if "FAIL" in statuses:
        return "FAIL"
    if "INCONCLUSIVE" in statuses:
        return "INCONCLUSIVE"
    if "BLOCKED" in statuses:
        return "BLOCKED"
    return "PASS"


def _redact_streams(value: Any) -> Any:
    if isinstance(value, list):
        return [_redact_streams(item) for item in value]
    if not isinstance(value, dict):
        return value
    redacted: dict[str, Any] = {}
    for key, item in value.items():
        if key in {"stdout", "stderr", "output"} and isinstance(item, str):
            encoded = item.encode("utf-8")
            redacted[f"{key}_sha256"] = hashlib.sha256(encoded).hexdigest()
            redacted[f"{key}_redacted"] = True
            continue
        if key == "command" and isinstance(item, list) and "--_qa-helper" in item:
            command = list(item)
            marker_index = command.index("--marker") + 1
            if marker_index < len(command):
                command[marker_index] = "<redacted-marker>"
            redacted[key] = command
            continue
        redacted[key] = _redact_streams(item)
    return redacted


def _write_report(descriptor: int, report: dict[str, Any]) -> None:
    payload = json.dumps(
        _redact_streams(report), indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8") + b"\n"
    with os.fdopen(descriptor, "wb", closefd=True) as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    canonical = args.canonical.resolve()
    short = args.short.resolve()
    binary_info = [validate_binary(canonical), validate_binary(short)]
    windows_tui_evidence = None
    if args.windows_tui_evidence is not None:
        windows_tui_evidence = read_windows_tui_evidence(
            args.windows_tui_evidence.resolve(), binary_info[0]["sha256"]
        )
    repository_context = _git_context()
    output_descriptor = reserve_output(args.output)
    report: dict[str, Any] = {
        "report": "kickoutchi.release_qa",
        "version": REPORT_VERSION,
        "started_unix_ms": int(time.time() * 1000),
        "finished_unix_ms": None,
        "overall": "INCONCLUSIVE",
        "first_failure": None,
        "context": _context(binary_info),
        "candidate": {
            "source_commit": args.candidate_commit,
            "archive_sha256": args.archive_sha256,
        },
        "repository": repository_context,
        "authorization": {
            "target": "isolated local release artifacts and harness-owned processes, sockets, files, and configuration",
            "allowed_actions": ["read native socket/process metadata", "bind loopback sockets", "terminate only a helper PID created by this harness"],
            "stop_conditions": ["bounded command timeout", "bounded output", "first observed product failure is retained without retry"],
            "cleanup_plan": "reap every helper, close every socket, and remove the isolated temporary tree",
        },
        "isolation": {},
        "helpers": [],
        "checks": [],
        "cleanup": [],
    }
    try:
        with tempfile.TemporaryDirectory(prefix="kickoutchi-release-qa-") as temporary:
            root = Path(temporary)
            env = _isolated_environment(root)
            report["isolation"] = {
                "root": str(root),
                "explicit_config_on_every_product_command": True,
                "home": env["HOME"],
                "config_home": env["XDG_CONFIG_HOME"],
                "temp": env["TMPDIR"],
                "removed_after_run": False,
            }
            session = QaSession(
                canonical,
                short,
                root,
                env,
                args.timeout,
                report,
                windows_tui_evidence,
            )
            try:
                session.setup()
                session.run()
            except Exception as error:
                report["checks"].append(
                    {
                        "name": "harness setup or dispatch",
                        "status": "INCONCLUSIVE",
                        "reason": str(error),
                        "traceback": traceback.format_exc(limit=8),
                        "evidence": {},
                    }
                )
            finally:
                session.cleanup()
        report["isolation"]["removed_after_run"] = not root.exists()
    except Exception as error:
        report["checks"].append(
            {
                "name": "isolated workspace lifecycle",
                "status": "INCONCLUSIVE",
                "reason": str(error),
                "traceback": traceback.format_exc(limit=8),
                "evidence": {},
            }
        )
    report["overall"] = _overall(report["checks"])
    report["finished_unix_ms"] = int(time.time() * 1000)
    try:
        _write_report(output_descriptor, report)
    except Exception:
        with contextlib.suppress(OSError):
            os.close(output_descriptor)
        raise
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2, "INCONCLUSIVE": 3}[report["overall"]]


if __name__ == "__main__":
    if "--_qa-helper" in sys.argv[1:]:
        raise SystemExit(_helper_main(sys.argv[1:]))
    raise SystemExit(main())
