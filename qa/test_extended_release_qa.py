import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from qa import extended_release_qa
from qa import release_qa


class ArgumentTests(unittest.TestCase):
    def test_requires_both_exact_artifact_hashes(self) -> None:
        with self.assertRaises(SystemExit):
            extended_release_qa.parse_args([])

        parsed = extended_release_qa.parse_args(
            [
                "--candidate", "candidate", "--candidate-sha256", "a" * 64,
                "--baseline", "baseline", "--baseline-sha256", "b" * 64,
                "--candidate-commit", "c" * 40, "--output", "report.json",
            ]
        )
        self.assertEqual(parsed.candidate, Path("candidate"))
        self.assertEqual(parsed.baseline_sha256, "b" * 64)

    def test_rejects_noncanonical_artifact_identity(self) -> None:
        for candidate_hash, commit in (("A" * 64, "c" * 40), ("a" * 64, "short")):
            with self.subTest(candidate_hash=candidate_hash, commit=commit), self.assertRaises(SystemExit):
                extended_release_qa.parse_args(
                    [
                        "--candidate", "candidate", "--candidate-sha256", candidate_hash,
                        "--baseline", "baseline", "--baseline-sha256", "b" * 64,
                        "--candidate-commit", commit, "--output", "report.json",
                    ]
                )


class WhyContractTests(unittest.TestCase):
    def document(self) -> dict:
        addresses = ["127.0.0.1", "0.0.0.0", "::1", "::"]
        return {
            "schema": "kickoutchi.why",
            "version": 1,
            "query": {"port": 4242, "protocols": ["tcp", "udp"], "addresses": addresses},
            "aggregate_exit_code": 0,
            "results": [
                {
                    "endpoint": {"protocol": protocol, "address": address, "port": 4242},
                    "verdict": "bindable_now",
                    "probe": {"outcome": "bindable_now"},
                }
                for protocol in ("tcp", "udp")
                for address in addresses
            ],
        }

    def test_accepts_exact_protocol_major_eight_endpoint_matrix(self) -> None:
        results = extended_release_qa.validate_why_document(
            self.document(),
            port=4242,
            protocols=["tcp", "udp"],
            addresses=["127.0.0.1", "0.0.0.0", "::1", "::"],
        )
        self.assertEqual(len(results), 8)

    def test_rejects_missing_reordered_or_wrong_endpoint(self) -> None:
        cases = []
        missing = self.document(); missing["results"].pop(); cases.append(missing)
        reordered = self.document(); reordered["results"][0], reordered["results"][1] = reordered["results"][1], reordered["results"][0]; cases.append(reordered)
        wrong = self.document(); wrong["results"][0]["endpoint"]["port"] = 4243; cases.append(wrong)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(release_qa.ProductFailure):
                extended_release_qa.validate_why_document(
                    value,
                    port=4242,
                    protocols=["tcp", "udp"],
                    addresses=["127.0.0.1", "0.0.0.0", "::1", "::"],
                )

    def test_rejects_unknown_verdict_and_probe_outcome(self) -> None:
        for field, value in (("verdict", "maybe"), ("probe", {"outcome": "maybe"})):
            document = self.document()
            document["results"][0][field] = value
            with self.subTest(field=field), self.assertRaises(release_qa.ProductFailure):
                extended_release_qa.validate_why_document(
                    document,
                    port=4242,
                    protocols=["tcp", "udp"],
                    addresses=["127.0.0.1", "0.0.0.0", "::1", "::"],
                )


class ResourceLifecycleTests(unittest.TestCase):
    def test_fixed_listener_owns_and_releases_its_port(self) -> None:
        listener = extended_release_qa.FixedListener("tcp", "127.0.0.1", 0)
        port = listener.port
        with self.assertRaises(OSError):
            extended_release_qa.FixedListener("tcp", "127.0.0.1", port)
        listener.close()
        replacement = extended_release_qa.FixedListener("tcp", "127.0.0.1", port)
        replacement.close()

    def test_controlled_command_interrupts_and_reaps_its_process(self) -> None:
        if os.name == "nt":
            self.skipTest("signal behavior is covered by native Windows execution")
        with tempfile.TemporaryDirectory() as temporary:
            ready = Path(temporary) / "ready"
            command = extended_release_qa.ControlledCommand(
                [
                    sys.executable,
                    "-c",
                    "import pathlib,signal,sys,time; signal.signal(signal.SIGINT, lambda *_: sys.exit(0)); pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(30)",
                    str(ready),
                ],
                env=dict(os.environ),
                cwd=Path(temporary),
            )
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists())
            command.interrupt()
            result = command.finish(3)
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["exit_code"], 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(result["pid"], 0)

    def test_pid_alive_treats_reaped_child_as_dead(self) -> None:
        result = release_qa.run_command(
            [sys.executable, "-c", "pass"],
            env=dict(os.environ),
            cwd=Path.cwd(),
            timeout=3,
        )
        self.assertFalse(extended_release_qa._pid_alive(result["pid"]))

    def test_session_cleanup_reaps_an_aborted_controlled_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("home", "config-home", "temp", "appdata"):
                (root / name).mkdir()
            session = extended_release_qa.Session(
                Path("candidate"), Path("baseline"), root, dict(os.environ), 3, {"checks": []}
            )
            command = extended_release_qa.ControlledCommand(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                env=dict(os.environ),
                cwd=root,
            )
            session.controlled_commands.append(command)
            pid = command.process.pid

            notes = session.cleanup()

        self.assertTrue(release_qa._cleanup_proven(notes))
        if os.name == "posix":
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


class PlatformContractTests(unittest.TestCase):
    def test_windows_scope_contract_never_claims_wsl_execution(self) -> None:
        source = Path(extended_release_qa.__file__).read_text(encoding="utf-8")
        self.assertIn('"wsl_network_stack_excluded"', source)
        self.assertIn('"wsl_execution_claimed": False', source)

    def test_fault_fixture_targets_only_the_required_linux_table(self) -> None:
        source = Path(extended_release_qa.__file__).with_name("watch_fault_fixture.c").read_text(encoding="utf-8")
        self.assertIn('strcmp(path, "/proc/net/tcp")', source)
        self.assertNotIn("/proc/net/udp", source)

    @unittest.skipUnless(sys.platform.startswith("linux"), "procfs fixture is Linux-only")
    def test_fault_fixture_denies_only_selected_collection_attempt(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        source = Path(extended_release_qa.__file__).with_name("watch_fault_fixture.c")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            library = root / "fixture.so"
            subprocess.run(
                [compiler, "-shared", "-fPIC", "-O2", "-o", str(library), str(source), "-ldl"],
                check=True,
                timeout=10,
            )
            state = root / "state"
            environment = dict(os.environ)
            environment.update(
                LD_PRELOAD=str(library),
                KICKOUTCHI_QA_FAULT_STATE=str(state),
                KICKOUTCHI_QA_FAULT_PLAN="1",
            )
            first = subprocess.run(
                [sys.executable, "-c", "open('/proc/net/tcp').read(1)"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=5,
            )
            second = subprocess.run(
                [sys.executable, "-c", "open('/proc/net/tcp').read(1)"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=5,
            )

        self.assertNotEqual(first.returncode, 0)
        self.assertIn("PermissionError", first.stderr)
        self.assertEqual(second.returncode, 0)


if __name__ == "__main__":
    unittest.main()
