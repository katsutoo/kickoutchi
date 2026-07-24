from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any
import uuid

try:
    from qa.terminal_screen import render_terminal_screen
except ModuleNotFoundError:
    from terminal_screen import render_terminal_screen

TIMEOUT_SECONDS = 15.0
STREAM_BYTES_MAX = 4 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_file(path: Path, label: str, *, allow_empty: bool = False) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-link file")
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError(f"{label} is oversized")
    data = path.read_bytes()
    if not data and not allow_empty:
        raise ValueError(f"{label} must be nonempty")
    if len(data) > 128 * 1024 * 1024:
        raise ValueError(f"{label} is oversized")
    return data


def terminate_process_tree(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        result = subprocess.run(
            ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def write_report(path: Path, report: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if os.name != "nt":
        parser.error("the ConPTY smoke is valid only on Windows")
    binary_data = regular_file(args.binary, "binary")
    regular_file(args.config, "config", allow_empty=True)
    binary = args.binary.resolve(strict=True)
    config = args.config.resolve(strict=True)
    output = args.output.resolve(strict=False)
    if output.exists():
        parser.error(f"refusing to overwrite {output}")
    winpty = importlib.import_module("winpty")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    label = f"qa-conpty-{uuid.uuid4().hex[:10]}"
    config.write_text(
        "[[ports]]\n"
        'protocol = "tcp"\n'
        'address = "127.0.0.1"\n'
        f"port = {listener.getsockname()[1]}\n"
        f'label = "{label}"\n',
        encoding="utf-8",
        newline="\n",
    )
    terminal = winpty.PTY(140, 30, backend=winpty.Backend.ConPTY, timeout=100)
    command_line = " " + subprocess.list2cmdline(["--config", str(config)])
    started = terminal.spawn(str(binary), cmdline=command_line, cwd=str(binary.parent))
    captured = bytearray()
    timed_out = False
    oversized = False
    diagnostic = ""
    sent_search = False
    sent_quit = False
    label_visible = False
    search_applied = False
    cleanup_verified = False
    started_at = time.monotonic()
    deadline = started_at + TIMEOUT_SECONDS
    try:
        while terminal.isalive() and time.monotonic() < deadline:
            chunk = terminal.read(blocking=False)
            if chunk:
                encoded = chunk.encode("utf-8")
                remaining = STREAM_BYTES_MAX + 1 - len(captured)
                captured.extend(encoded[: max(remaining, 0)])
                if len(captured) > STREAM_BYTES_MAX:
                    oversized = True
                    break
            screen = render_terminal_screen(bytes(captured), 30, 141)
            entered = b"\x1b[?1049h" in captured
            label_visible = label in screen
            search_applied = f"filter: {label}" in screen.lower()
            if entered and not sent_search:
                terminal.write(f"/{label}\r")
                terminal.set_size(141, 30)
                sent_search = True
            if search_applied and not sent_quit:
                terminal.write("q")
                sent_quit = True
            time.sleep(0.01)
        if terminal.isalive():
            timed_out = not oversized
            terminate_process_tree(terminal.pid)
        drain_deadline = time.monotonic() + 1.0
        while time.monotonic() < drain_deadline and len(captured) <= STREAM_BYTES_MAX:
            chunk = terminal.read(blocking=False)
            if chunk:
                encoded = chunk.encode("utf-8")
                remaining = STREAM_BYTES_MAX + 1 - len(captured)
                captured.extend(encoded[: max(remaining, 0)])
                continue
            if terminal.iseof() or not terminal.isalive():
                break
            time.sleep(0.01)
    except Exception as error:
        diagnostic = f"{type(error).__name__}: {error}"[:1024]
    finally:
        if terminal.isalive():
            terminate_process_tree(terminal.pid)
            terminal.cancel_io()
        cleanup_deadline = time.monotonic() + 1.0
        while terminal.isalive() and time.monotonic() < cleanup_deadline:
            time.sleep(0.01)
        cleanup_verified = not terminal.isalive()
        listener.close()

    oversized = oversized or len(captured) > STREAM_BYTES_MAX
    entered = b"\x1b[?1049h" in captured
    left = b"\x1b[?1049l" in captured
    exit_code = terminal.get_exitstatus()
    passed = (
        started
        and exit_code == 0
        and not timed_out
        and not oversized
        and entered
        and left
        and cleanup_verified
        and label_visible
        and search_applied
        and not diagnostic
    )
    report = {
        "schema": "kickoutchi.windows_tui_smoke",
        "version": 1,
        "status": "PASS" if passed else "FAIL",
        "mechanism": "conpty",
        "binary_sha256": sha256(binary_data),
        "pywinpty_version": winpty.__version__,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "output_oversized": oversized,
        "entered_alternate_screen": entered,
        "left_alternate_screen": left,
        "cleanup_verified": cleanup_verified,
        "label_visible": label_visible,
        "search_applied": search_applied,
        "terminal_output_bytes": len(captured),
        "terminal_output_sha256": sha256(bytes(captured)),
        "harness_diagnostic": diagnostic,
    }
    write_report(output, report)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
