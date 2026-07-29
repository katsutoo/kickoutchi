import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import run as benchmark  # noqa: E402


class BenchmarkContractTests(unittest.TestCase):
    def test_percentile_uses_nearest_rank(self) -> None:
        values = list(range(1, 101))
        self.assertEqual(benchmark.percentile(values, 0.50), 50.0)
        self.assertEqual(benchmark.percentile(values, 0.95), 95.0)
        self.assertEqual(benchmark.percentile(values, 0.99), 99.0)

    def test_change_requires_practical_and_noise_thresholds(self) -> None:
        baseline = [10.0, 10.2, 9.8, 10.1, 9.9] * 2
        within_noise = [10.1, 10.1, 10.0, 10.0, 10.0] * 2
        regression = [12.0, 12.2, 11.8, 12.1, 11.9] * 2

        self.assertEqual(
            benchmark.classify_wall_change(
                baseline, within_noise, absolute_threshold_ms=0.5
            )[0],
            "within noise",
        )
        self.assertEqual(
            benchmark.classify_wall_change(
                baseline, regression, absolute_threshold_ms=0.5
            )[0],
            "regression",
        )

    def test_spawn_reports_per_process_usage_and_exit_status(self) -> None:
        true_binary = Path("/bin/true")
        if not true_binary.exists():
            self.skipTest("/bin/true is unavailable")
        with tempfile.TemporaryDirectory(prefix="kickoutchi-benchmark-test-") as root:
            environment = benchmark.benchmark_environment(Path(root))
            measurement = benchmark.run_once(
                true_binary,
                (),
                environment,
                timeout_seconds=1.0,
                evict_binary=False,
            )

        self.assertEqual(measurement.exit_code, 0)
        self.assertFalse(measurement.timed_out)
        self.assertGreater(measurement.wall_ms, 0.0)
        self.assertGreater(measurement.max_rss_kib, 0)


if __name__ == "__main__":
    unittest.main()
