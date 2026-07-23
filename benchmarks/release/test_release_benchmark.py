#!/usr/bin/env python3
import copy
import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.release.common import (
    EvidenceError,
    balanced_orders,
    nearest_rank,
    require_absent,
    validate_plan,
)
from benchmarks.release.summarize import classify_comparison, parse_rows


PLAN_PATH = Path(__file__).with_name("plan.json")


class PlanValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))

    def test_shipped_plan_is_valid_and_declares_required_sample_shapes(self) -> None:
        validate_plan(self.plan)
        fast = [item for item in self.plan["workloads"] if item["comparison"] == "baseline_candidate"]
        fast_process = [item for item in self.plan["workloads"] if item["kind"] in {"list", "snapshot", "why"}]
        watch = next(item for item in self.plan["workloads"] if item["kind"] == "watch")
        self.assertTrue(all(item["blocks"] == 10 and item["samples_per_block"] == 1000 for item in fast))
        self.assertTrue(all(10 <= item["warmups"] <= 20 for item in fast))
        self.assertTrue(all(item["blocks"] * item["samples_per_block"] >= 10_000 for item in fast_process))
        self.assertEqual(watch["blocks"] * watch["samples_per_block"], 2000)

    def test_odd_comparison_samples_are_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["workloads"][0]["samples_per_block"] = 999
        with self.assertRaisesRegex(EvidenceError, "even"):
            validate_plan(changed)

    def test_baseline_comparison_for_new_command_is_rejected(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["workloads"][2]["comparison"] = "baseline_candidate"
        with self.assertRaisesRegex(EvidenceError, "only list"):
            validate_plan(changed)


class OrderingAndPercentileTests(unittest.TestCase):
    def test_seeded_orders_are_repeatable_and_exactly_balanced(self) -> None:
        first = balanced_orders(42, "list", 3, 1000)
        second = balanced_orders(42, "list", 3, 1000)
        self.assertEqual(first, second)
        self.assertEqual(first.count(("left", "right")), 500)
        self.assertEqual(first.count(("right", "left")), 500)

    def test_nearest_rank_percentiles_do_not_interpolate(self) -> None:
        values = list(range(1, 101))
        self.assertEqual(nearest_rank(values, 50), 50)
        self.assertEqual(nearest_rank(values, 95), 95)
        self.assertEqual(nearest_rank(values, 99), 99)


class InputRefusalTests(unittest.TestCase):
    def test_existing_output_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.jsonl"
            output.write_text("owned", encoding="utf-8")
            with self.assertRaisesRegex(EvidenceError, "already exists"):
                require_absent(output)
            self.assertEqual(output.read_text(encoding="utf-8"), "owned")

    def test_malformed_jsonl_is_rejected_with_line_number(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "line 1"):
            parse_rows(b"{not-json}\n", "0" * 64)


class ClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.budgets = {
            "p50_delta_percent_max": 10.0,
            "p95_delta_percent_max": 15.0,
            "p99_delta_percent_max": 20.0,
            "p99_latency_ns_max": 1_000,
            "max_delta_percent_max": 100.0,
            "cpu_delta_percent_max": 20.0,
            "rss_delta_percent_max": 20.0,
        }
        self.baseline = {
            "failures": 0, "p50_latency_ns": 100, "p95_latency_ns": 100,
            "p99_latency_ns": 100, "max_latency_ns": 100, "p50_cpu_ns": 100,
            "peak_memory_bytes": 100,
        }

    def test_passes_below_practical_budgets(self) -> None:
        candidate = {key: (105 if isinstance(value, int) and key != "failures" else value) for key, value in self.baseline.items()}
        verdict, reasons, _ = classify_comparison(self.budgets, self.baseline, candidate, 2.0, 5.0, 1.5)
        self.assertEqual((verdict, reasons), ("PASS", []))

    def test_fails_practical_regression_above_noise(self) -> None:
        candidate = dict(self.baseline, p99_latency_ns=130)
        verdict, reasons, _ = classify_comparison(self.budgets, self.baseline, candidate, 2.0, 5.0, 1.5)
        self.assertEqual(verdict, "FAIL")
        self.assertIn("p99_latency_ns", reasons[0])

    def test_high_aa_noise_is_inconclusive(self) -> None:
        verdict, reasons, _ = classify_comparison(self.budgets, self.baseline, self.baseline, 6.0, 5.0, 1.5)
        self.assertEqual(verdict, "INCONCLUSIVE")
        self.assertIn("A/A", reasons[0])

    def test_validation_failure_always_fails(self) -> None:
        candidate = dict(self.baseline, failures=1)
        verdict, _, _ = classify_comparison(self.budgets, self.baseline, candidate, 20.0, 5.0, 1.5)
        self.assertEqual(verdict, "FAIL")


if __name__ == "__main__":
    unittest.main()
