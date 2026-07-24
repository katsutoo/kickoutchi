#!/usr/bin/env python3
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from benchmarks.release.common import EvidenceError, REQUIRED_WORKLOADS, balanced_orders, nearest_rank, require_absent, validate_plan
from benchmarks.release.controller import invoke, smoke_workload, validate_output
from benchmarks.release.summarize import classify, distribution, parse_rows, summarize, validate_manifest, validate_row_artifacts

PLAN_PATH = Path(__file__).with_name("plan.json")
CONTROLLER_PATH = Path(__file__).with_name("controller.py")


def workload(plan: dict, name: str) -> dict:
    return next(item for item in plan["workloads"] if item["name"] == name)


class PlanValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))

    def test_draft_has_the_exact_required_matrix_and_final_sample_shapes(self) -> None:
        validate_plan(self.plan, require_gate_ready=False)
        self.assertEqual({item["name"] for item in self.plan["workloads"]}, REQUIRED_WORKLOADS)
        fast = [item for item in self.plan["workloads"] if item["sampling"]["profile"] == "fast_process"]
        long = [item for item in self.plan["workloads"] if item["sampling"]["profile"] == "long_process"]
        self.assertTrue(all((item["sampling"]["blocks"], item["sampling"]["samples_per_block"]) == (10, 1000) for item in fast))
        self.assertTrue(all(item["sampling"]["blocks"] * item["sampling"]["samples_per_block"] == 2000 for item in long))

    def test_gate_collection_refuses_the_draft(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "not ready"):
            validate_plan(self.plan)

    def test_gate_ready_refuses_any_unimplemented_workload(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["gate_ready"] = True
        changed["protocol_identity"] = {"harness_commit":"a" * 40,"harness_tree_sha256":"b" * 64,"included_product_sources_sha256":"f" * 64,"diff_helper_source_sha256":"c" * 64,"diff_helper_lock_sha256":"d" * 64,"diff_helper_sha256_by_platform":{"linux-x86_64":"e" * 64},"rust_target":"x86_64-unknown-linux-gnu","rustc_version":"rustc test"}
        with self.assertRaisesRegex(EvidenceError, "unimplemented"):
            validate_plan(changed)

    def test_declared_implemented_flag_cannot_bypass_an_unavailable_driver(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["gate_ready"] = True
        changed["protocol_identity"] = {"harness_commit":"a" * 40,"harness_tree_sha256":"b" * 64,"included_product_sources_sha256":"f" * 64,"diff_helper_source_sha256":"c" * 64,"diff_helper_lock_sha256":"d" * 64,"diff_helper_sha256_by_platform":{"linux-x86_64":"e" * 64},"rust_target":"x86_64-unknown-linux-gnu","rustc_version":"rustc test"}
        for item in changed["workloads"]:
            item["implemented"] = True
        with self.assertRaisesRegex(EvidenceError, "unavailable workload driver"):
            validate_plan(changed)

    def test_unknown_plan_and_workload_keys_are_rejected(self) -> None:
        for changed, message in ((copy.deepcopy(self.plan), "plan keys"), (copy.deepcopy(self.plan), "workload keys")):
            if message == "plan keys": changed["surprise"] = True
            else: changed["workloads"][0]["surprise"] = True
            with self.subTest(message=message), self.assertRaisesRegex(EvidenceError, "unknown"):
                validate_plan(changed, require_gate_ready=False)

    def test_unknown_budget_and_missing_absolute_budget_are_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        workload(changed, "list_typical")["budgets"]["absolute_max"]["made_up"] = 1
        with self.assertRaisesRegex(EvidenceError, "unknown"):
            validate_plan(changed, require_gate_ready=False)
        changed = copy.deepcopy(self.plan)
        item = workload(changed, "list_typical")
        item["budgets"]["absolute_max"] = {}; item["budgets"]["absolute_min"] = {}
        with self.assertRaisesRegex(EvidenceError, "absolute"):
            validate_plan(changed, require_gate_ready=False)

    def test_required_name_cannot_hide_a_different_workload_or_fixture(self) -> None:
        changed = copy.deepcopy(self.plan)
        workload(changed, "watch_high_churn")["kind"] = "snapshot"
        with self.assertRaisesRegex(EvidenceError, "signature"):
            validate_plan(changed, require_gate_ready=False)
        changed = copy.deepcopy(self.plan)
        workload(changed, "diff_maximum_replacement")["fixture"]["churn_events"] -= 1
        with self.assertRaisesRegex(EvidenceError, "fixture"):
            validate_plan(changed, require_gate_ready=False)

    def test_startup_semantics_are_distinct_and_smoke_is_bounded(self) -> None:
        cold, warm = workload(self.plan, "startup_list_cold"), workload(self.plan, "startup_list_warm")
        self.assertEqual((cold["startup"], warm["startup"]), ("cold", "warm"))
        self.assertIn("fresh", cold["scenario"]); self.assertIn("reused", warm["scenario"])
        self.assertEqual(smoke_workload(cold)["sampling"], {"profile":"fast_process","blocks":1,"samples_per_block":4,"warmups":1})


class OrderingAndPercentileTests(unittest.TestCase):
    def test_seeded_order_is_repeatable_and_balanced(self) -> None:
        orders = balanced_orders(42, "list", 3, 1000)
        self.assertEqual(orders, balanced_orders(42, "list", 3, 1000))
        self.assertEqual(orders.count(("left", "right")), 500)
        self.assertEqual(orders.count(("right", "left")), 500)

    def test_nearest_rank_does_not_interpolate(self) -> None:
        values = list(range(1, 101))
        self.assertEqual((nearest_rank(values, 50), nearest_rank(values, 95), nearest_rank(values, 99)), (50, 95, 99))


class ClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.budgets = {"failures_max":0,"absolute_max":{"latency_p99_ns":1000},"absolute_min":{},"relative_delta_percent_max":{"latency_p99_ns":20.0,"cpu_p50_ns":20.0}}
        self.calibration = {"mode":"baseline_aa","metric_noise_limit_percent":{"latency_p99_ns":5.0,"cpu_p50_ns":10.0},"multiplier":1.5}
        self.baseline = {"failures":0,"latency_p99_ns":100,"cpu_p50_ns":100}

    def test_absolute_failure_precedes_excessive_noise(self) -> None:
        verdict, reasons, _ = classify(self.budgets, self.baseline, {"failures":0,"latency_p99_ns":1001,"cpu_p50_ns":100}, {"latency_p99_ns":99.0,"cpu_p50_ns":0.0}, self.calibration)
        self.assertEqual(verdict, "FAIL"); self.assertIn("absolute", reasons[0])

    def test_metric_specific_noise_does_not_hide_another_metric(self) -> None:
        candidate = {"failures":0,"latency_p99_ns":130,"cpu_p50_ns":130}
        verdict, reasons, _ = classify(self.budgets, self.baseline, candidate, {"latency_p99_ns":2.0,"cpu_p50_ns":25.0}, self.calibration)
        self.assertEqual(verdict, "FAIL")
        self.assertTrue(any("latency_p99_ns" in reason for reason in reasons))

    def test_candidate_only_calibration_can_withhold(self) -> None:
        candidate_budgets = {"failures_max":0,"absolute_max":{"latency_p99_ns":1000},"absolute_min":{},"relative_delta_percent_max":{}}
        verdict, reasons, _ = classify(candidate_budgets, None, {"failures":0,"latency_p99_ns":100}, {"latency_p99_ns":8.0}, {"mode":"candidate_paired","metric_noise_limit_percent":{"latency_p99_ns":5.0},"multiplier":1.5})
        self.assertEqual(verdict, "INCONCLUSIVE"); self.assertIn("calibration noise", reasons[0])

    def test_missing_absolute_metric_is_never_a_pass(self) -> None:
        verdict, reasons, _ = classify(self.budgets, self.baseline, {"failures":0,"cpu_p50_ns":100}, {"latency_p99_ns":0.0,"cpu_p50_ns":0.0}, self.calibration)
        self.assertEqual(verdict, "INCONCLUSIVE"); self.assertIn("unavailable", reasons[0])


class OutputValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))

    @staticmethod
    def result(stdout: bytes, status: int = 0, stderr: bytes = b"") -> dict:
        return {"status":status,"stdout":stdout,"stderr":stderr,"stdout_bytes":len(stdout),"stderr_bytes":len(stderr),"timed_out":False,"stream_exceeded":False}

    def test_list_requires_exact_contract_and_controlled_endpoint(self) -> None:
        item = workload(self.plan, "list_typical")
        row = {"protocol":"tcp","local_addr":"127.0.0.1","local_port":32001,"state":"listen","pid":1,"process_name":"p","executable_path":None,"command_line":None,"parent_pid":None,"parent_process_name":None,"child_pids":[],"protected":False,"platform":"linux","permission":"full","label":None}
        valid = validate_output(item, self.result(json.dumps([row]).encode()), {("tcp","127.0.0.1",32001)})
        self.assertTrue(valid[0])
        row["unknown"] = 1
        self.assertEqual(validate_output(item, self.result(json.dumps([row]).encode()), set())[3], "invalid_list_contract")

    def test_success_with_stderr_is_rejected(self) -> None:
        item = workload(self.plan, "list_empty")
        self.assertEqual(validate_output(item, self.result(b"[]", stderr=b"warning"), set())[3], "nonempty_stderr")

    def test_diff_helper_requires_exact_count_and_exhaustion(self) -> None:
        item = workload(self.plan, "diff_typical")
        document = {"schema":"kickoutchi.release_diff_helper","version":1,"scenario":"typical","input_sockets":1024,"scanned_sockets":2048,"events":1024,"iterator_exhausted":True,"checksum":1,"engine_duration_ns":250}
        validated = validate_output(item, self.result(json.dumps(document).encode()), set())
        self.assertEqual(validated, (True, 1024, 1024, None, 250, 2048))
        document["iterator_exhausted"] = False
        self.assertEqual(validate_output(item, self.result(json.dumps(document).encode()), set())[3], "invalid_diff_helper_output")

    def test_diff_helper_rejects_old_or_extra_keys(self) -> None:
        item = workload(self.plan, "diff_typical")
        document = {"schema":"kickoutchi.release_diff_helper","version":1,"scenario":"typical","input_sockets":1024,"scanned_sockets":2048,"events":1024,"iterator_exhausted":True,"checksum":1,"engine_duration_ns":250}
        for changed in (dict(document, scanned_count=2048), {key:value for key, value in document.items() if key != "scanned_sockets"}):
            with self.subTest(keys=set(changed)):
                self.assertEqual(validate_output(item, self.result(json.dumps(changed).encode()), set())[3], "invalid_diff_helper_output")

    def test_streamed_but_unretained_output_cannot_bypass_validation(self) -> None:
        item = workload(self.plan, "snapshot_empty")
        result = self.result(b"{}"); result["stdout_bytes"] = 100
        self.assertEqual(validate_output(item, result, set())[3], "output_not_retained_for_validation")


class ProcessAndEvidenceTests(unittest.TestCase):
    @staticmethod
    def observation(**changes: object) -> dict:
        row = {"outcome":"valid","error":None,"status":0,"latency_ns":1_000,"operation_duration_ns":None,"scanned_count":None,
               "user_cpu_ns":100,"system_cpu_ns":100,"peak_memory_bytes":1000,"block":1,"row_count":10,"event_count":5,
               "workload":"list_typical","artifact_role":"candidate","artifact_sha256":"c" * 64,"artifact_bytes":20}
        row.update(changes)
        return row

    def test_diff_throughput_uses_engine_duration_and_scan_count(self) -> None:
        rows = [self.observation(operation_duration_ns=100, scanned_count=40, row_count=20, event_count=10)]
        result = distribution(rows)
        self.assertEqual(result["measurement_duration_ns"], 1_000)
        self.assertEqual(result["operation_duration_ns"], 100)
        self.assertEqual(result["throughput_rows_per_second"], 400_000_000)
        self.assertEqual(result["throughput_events_per_second"], 100_000_000)

    def test_candidate_only_summary_combines_calibration_sides_and_failures(self) -> None:
        plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
        plan["workloads"] = [workload(plan, "snapshot_typical")]
        manifest = {"skipped_workloads":[],"artifacts":{"baseline":{"bytes":10},"candidate":{"bytes":20}},"gate_eligible":True,"mode":"final","plan_sha256":"p","raw_sha256":"r"}
        rows = [self.observation(workload="snapshot_typical", lane="calibration", lane_side="left", latency_ns=100),
                self.observation(workload="snapshot_typical", lane="calibration", lane_side="right", latency_ns=200, outcome="error", error="bad")]
        report = summarize(plan, manifest, rows)["workloads"][0]
        self.assertEqual(report["candidate"]["samples"], 1)
        self.assertEqual(report["candidate"]["failures"], 1)
        self.assertEqual(report["verdict"], "FAIL")

    def test_every_row_artifact_identity_is_checked_by_driver(self) -> None:
        plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
        manifest = {"artifacts":{"baseline":{"sha256":"b" * 64,"bytes":10},"candidate":{"sha256":"c" * 64,"bytes":20}},
                    "diff_helper_sha256":"d" * 64,"diff_helper_bytes":30}
        native = self.observation()
        helper = self.observation(workload="diff_typical", artifact_sha256="d" * 64, artifact_bytes=30)
        validate_row_artifacts(plan, manifest, [native, helper])
        for changed in (dict(native, artifact_bytes=21), dict(helper, artifact_sha256="e" * 64)):
            with self.subTest(row=changed["workload"]), self.assertRaisesRegex(EvidenceError, "artifact identity"):
                validate_row_artifacts(plan, manifest, [changed])

    def test_manifest_records_reviewed_and_checkout_commits_and_early_start(self) -> None:
        source = CONTROLLER_PATH.read_text(encoding="utf-8")
        self.assertIn('"harness_commit":plan["protocol_identity"]["harness_commit"]', source)
        self.assertIn('"checkout_commit":_git_commit()', source)
        self.assertLess(source.index("started_utc ="), source.index("snapshot_executable(args.baseline"))

    def test_manifest_schema_requires_both_commit_identities(self) -> None:
        plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
        platform_key = "linux-x86_64"
        manifest = {"schema":"kickoutchi.release_benchmark_manifest","version":2,"plan_sha256":"a" * 64,"raw_sha256":"b" * 64,
                    "mode":"smoke","gate_eligible":False,"complete":True,"started_utc":"2026-07-24T12:00:00+00:00","duration_ns":1,
                    "source_commit":plan["artifacts"]["candidate"]["source_commit"],"harness_commit":None,"checkout_commit":"c" * 40,
                    "platform_key":platform_key,"environment":{"compiler":"x","target":"x","cpu":"x","cpu_count":1,"ram_bytes":1,"os":"x","kernel":"x","power":{},"thermal":{},"concurrent_load":None,"python":"x"},
                    "commands":{},"versions":{"baseline":"kickoutchi 1.2.0","candidate":"kickoutchi 1.3.0"},"diff_helper_sha256":None,"diff_helper_bytes":None,
                    "artifacts":{"baseline":{"sha256":plan["artifacts"]["baseline"]["sha256_by_platform"][platform_key],"bytes":1},"candidate":{"sha256":plan["artifacts"]["candidate"]["sha256_by_platform"][platform_key],"bytes":1}},
                    "row_count":0,"failure_count":0,"skipped_workloads":[item["name"] for item in plan["workloads"]],"notes":[]}
        validate_manifest(plan, manifest)
        for changed in ({key:value for key, value in manifest.items() if key != "checkout_commit"}, dict(manifest, surprise=True)):
            with self.subTest(keys=set(changed)), self.assertRaisesRegex(EvidenceError, "exact keys"):
                validate_manifest(plan, changed)

    def test_bounded_capture_hashes_the_complete_allowed_stream(self) -> None:
        payload = b"x" * 50
        result = invoke(Path(sys.executable), ["-c", "import sys; sys.stdout.buffer.write(b'x'*50)"], dict(os.environ), 2, 10, 100)
        self.assertEqual(result["stdout"], b"x" * 10)
        self.assertEqual(result["stdout_bytes"], 50)
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertFalse(result["stream_exceeded"])

    @unittest.skipUnless(os.name == "posix", "process-group assertion is POSIX-specific")
    def test_timeout_kills_the_owned_process_tree(self) -> None:
        code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); print(p.pid,flush=True); time.sleep(30)"
        result = invoke(Path(sys.executable), ["-c", code], dict(os.environ), 0.1, 1024, 1024)
        self.assertTrue(result["timed_out"])
        child = int(result["stdout"].strip())
        deadline = time.monotonic() + 2
        while Path(f"/proc/{child}").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(Path(f"/proc/{child}").exists())

    def test_windows_native_calls_declare_argument_and_result_types(self) -> None:
        source = CONTROLLER_PATH.read_text(encoding="utf-8")
        for function in ("CreateJobObjectW", "AssignProcessToJobObject", "TerminateJobObject", "GetProcessTimes", "GetProcessMemoryInfo", "GlobalMemoryStatusEx", "CloseHandle"):
            self.assertIn(f"{function}.argtypes", source)
            self.assertIn(f"{function}.restype", source)

    def test_existing_output_and_malformed_or_extra_row_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "raw"
            output.write_text("owned", encoding="utf-8")
            with self.assertRaisesRegex(EvidenceError, "already exists"):
                require_absent(output)
        with self.assertRaisesRegex(EvidenceError, "line 1"):
            parse_rows(b"{not-json}\n", "0" * 64)


if __name__ == "__main__":
    unittest.main()
