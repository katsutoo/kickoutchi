import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from qa import release_qa


class ArgumentTests(unittest.TestCase):
    def test_requires_explicit_binary_and_output_paths(self) -> None:
        with self.assertRaises(SystemExit):
            release_qa.parse_args([])

        parsed = release_qa.parse_args(
            [
                "--canonical", "one", "--short", "two", "--output", "report.json",
                "--candidate-commit", "a" * 40, "--archive-sha256", "b" * 64,
            ]
        )
        self.assertEqual(parsed.canonical, Path("one"))
        self.assertEqual(parsed.short, Path("two"))
        self.assertEqual(parsed.output, Path("report.json"))

    def test_timeout_is_bounded(self) -> None:
        for value in ("0", "301"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                release_qa.parse_args(
                    [
                        "--canonical",
                        "one",
                        "--short",
                        "two",
                        "--output",
                        "report.json",
                        "--timeout",
                        value,
                        "--candidate-commit",
                        "a" * 40,
                        "--archive-sha256",
                        "b" * 64,
                    ]
                )

    def test_artifact_identities_are_full_lowercase_hex(self) -> None:
        for commit, archive in (("A" * 40, "b" * 64), ("a" * 40, "nope")):
            with self.subTest(commit=commit, archive=archive), self.assertRaises(SystemExit):
                release_qa.parse_args(
                    [
                        "--canonical", "one", "--short", "two", "--output", "report.json",
                        "--candidate-commit", commit, "--archive-sha256", archive,
                    ]
                )


class ArtifactTests(unittest.TestCase):
    def test_binary_accepts_exact_limit_and_hashes_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "binary"
            path.write_bytes(b"abcd")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

            info = release_qa.validate_binary(path, max_bytes=4)

        self.assertEqual(info["size_bytes"], 4)
        self.assertEqual(
            info["sha256"],
            "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589",
        )

    def test_binary_rejects_missing_nonregular_empty_and_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            empty = root / "empty"
            empty.touch(mode=0o700)
            oversized = root / "oversized"
            oversized.write_bytes(b"12345")
            oversized.chmod(0o700)
            cases = (root / "missing", root, empty, oversized)

            for path in cases:
                with self.subTest(path=path), self.assertRaises(release_qa.HarnessError):
                    release_qa.validate_binary(path, max_bytes=4)

    @unittest.skipIf(os.name == "nt", "symbolic-link creation is not generally available")
    def test_binary_rejects_symbolic_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_bytes(b"binary")
            target.chmod(0o700)
            link = root / "link"
            link.symlink_to(target)

            with self.assertRaisesRegex(release_qa.HarnessError, "symbolic link"):
                release_qa.validate_binary(link)

    def test_output_reservation_refuses_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text("keep", encoding="utf-8")

            with self.assertRaises(release_qa.HarnessError):
                release_qa.reserve_output(path)

            self.assertEqual(path.read_text(encoding="utf-8"), "keep")


class StructuredParsingTests(unittest.TestCase):
    def test_ndjson_accepts_exact_record_and_count_bounds(self) -> None:
        line = json.dumps({"event": "baseline"}) + "\n"
        records = release_qa.parse_ndjson(
            line + line, record_max_bytes=len(line.encode()), records_max=2
        )
        self.assertEqual(records, [{"event": "baseline"}, {"event": "baseline"}])

    def test_ndjson_rejects_missing_newline_malformed_oversized_and_too_many(self) -> None:
        cases = (
            ("{}", 10, 1),
            ("{oops}\n", 10, 1),
            ("{}\n", 2, 1),
            ("{}\n{}\n", 10, 1),
        )
        for text, byte_limit, count_limit in cases:
            with self.subTest(text=text), self.assertRaises(release_qa.HarnessError):
                release_qa.parse_ndjson(
                    text, record_max_bytes=byte_limit, records_max=count_limit
                )

    def test_report_redacts_streams_and_helper_marker(self) -> None:
        report = {
            "stdout": "private process command line",
            "nested": {
                "stderr": "private diagnostic",
                "command": ["python", "--_qa-helper", "--marker", "private-marker"],
            },
        }

        redacted = release_qa._redact_streams(report)

        self.assertNotIn("stdout", redacted)
        self.assertTrue(redacted["stdout_redacted"])
        self.assertNotIn("stderr", redacted["nested"])
        self.assertEqual(redacted["nested"]["command"][-1], "<redacted-marker>")

    def test_macos_watch_limitation_accepts_only_exact_fail_closed_diagnostics(self) -> None:
        result = {"exit_code": 1, "stdout": "", "stderr": "error: initial observation has a partial socket set\n"}
        original = release_qa.platform.system
        release_qa.platform.system = lambda: "Darwin"
        try:
            self.assertEqual(release_qa._macos_watch_limitation(result), "partial_socket_set")
            changed = dict(result, stderr="error: unrelated failure\n")
            self.assertIsNone(release_qa._macos_watch_limitation(changed))
            changed = dict(result, stdout="{}\n")
            self.assertIsNone(release_qa._macos_watch_limitation(changed))
        finally:
            release_qa.platform.system = original

    @unittest.skipUnless(os.name == "nt", "Windows evidence is native-only")
    def test_windows_tui_evidence_requires_matching_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tui.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "kickoutchi.windows_tui_smoke",
                        "version": 1,
                        "status": "PASS",
                        "mechanism": "conpty",
                        "binary_sha256": "a" * 64,
                        "exit_code": 0,
                        "timed_out": False,
                        "output_oversized": False,
                        "entered_alternate_screen": True,
                        "left_alternate_screen": True,
                        "cleanup_verified": True,
                        "pywinpty_version": "3.0.5",
                        "terminal_output_bytes": 1,
                        "terminal_output_sha256": "c" * 64,
                        "harness_diagnostic": "",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(release_qa.HarnessError):
                release_qa.read_windows_tui_evidence(path, "b" * 64)


class CommandBoundTests(unittest.TestCase):
    def test_cleanup_notes_fail_closed_on_unreaped_or_termination_error(self) -> None:
        self.assertTrue(release_qa._cleanup_proven(["listener stopped and reaped"]))
        self.assertFalse(release_qa._cleanup_proven(["process did not reap before cleanup deadline"]))
        self.assertFalse(release_qa._cleanup_proven(["termination error: denied"]))

    def test_runner_bounds_stdout_and_stderr_without_deadlock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = release_qa.run_command(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('o'*8192); sys.stderr.write('e'*8192)",
                ],
                env=dict(os.environ),
                cwd=Path(temporary),
                timeout=5,
                output_limit=1024,
            )

        self.assertEqual(result["stdout_bytes_captured"], 1024)
        self.assertEqual(result["stderr_bytes_captured"], 1024)
        self.assertTrue(result["stdout_truncated"])
        self.assertTrue(result["stderr_truncated"])
        self.assertFalse(result["timed_out"])

    def test_runner_times_out_and_reaps_owned_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = release_qa.run_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                env=dict(os.environ),
                cwd=Path(temporary),
                timeout=0.1,
            )

        self.assertTrue(result["timed_out"])
        self.assertIsNotNone(result["exit_code"])
        if os.name == "posix":
            with self.assertRaises(ProcessLookupError):
                os.kill(result["pid"], 0)


if __name__ == "__main__":
    unittest.main()
