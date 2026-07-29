#!/usr/bin/env python3
"""Compare two optimized Kickoutchi binaries on one Linux host."""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import os
import platform
import random
import resource
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path

SAMPLES_MIN = 10
SAMPLES_MAX = 1_000
WARMUPS_MAX = 100
TIMEOUT_SECONDS_MAX = 60.0
POLL_SECONDS = 0.001
CORRECTNESS_OUTPUT_BYTES_MAX = 4 * 1024 * 1024
SEED_DEFAULT = 0x4B49_434B


@dataclasses.dataclass(frozen=True)
class Measurement:
    wall_ms: float
    user_ms: float
    system_ms: float
    max_rss_kib: int
    exit_code: int
    timed_out: bool

    def to_dict(self) -> dict[str, float | int | bool]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    arguments: tuple[str, ...]
    evict_binary: bool
    samples: int
    absolute_threshold_ms: float


def bounded_integer(raw: str, minimum: int, maximum: int, name: str) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise argparse.ArgumentTypeError(
            f"{name} must be between {minimum} and {maximum}"
        )
    return value


def bounded_float(raw: str, minimum: float, maximum: float, name: str) -> float:
    try:
        value = float(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{name} must be a number") from error
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise argparse.ArgumentTypeError(
            f"{name} must be between {minimum} and {maximum}"
        )
    return value


def percentile(values: Sequence[float | int], fraction: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    if not 0.0 <= fraction <= 1.0:
        raise ValueError("percentile fraction must be between zero and one")
    ordered = sorted(float(value) for value in values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def median_absolute_deviation(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("median absolute deviation requires at least one value")
    center = statistics.median(values)
    return statistics.median(abs(value - center) for value in values)


def classify_wall_change(
    baseline_ms: Sequence[float],
    candidate_ms: Sequence[float],
    *,
    absolute_threshold_ms: float,
    relative_threshold: float = 0.05,
) -> tuple[str, float, float]:
    if len(baseline_ms) != len(candidate_ms) or not baseline_ms:
        raise ValueError("paired non-empty measurements are required")
    baseline_median = statistics.median(baseline_ms)
    candidate_median = statistics.median(candidate_ms)
    paired_deltas = [
        candidate - baseline
        for baseline, candidate in zip(baseline_ms, candidate_ms, strict=True)
    ]
    delta_ms = candidate_median - baseline_median
    noise_ms = 1.4826 * median_absolute_deviation(paired_deltas)
    practical_ms = max(
        absolute_threshold_ms,
        baseline_median * relative_threshold,
        noise_ms * 3.0,
    )
    if delta_ms > practical_ms:
        verdict = "regression"
    elif delta_ms < -practical_ms:
        verdict = "improvement"
    else:
        verdict = "within noise"
    return verdict, delta_ms, practical_ms


def checked_binary(path: Path) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"binary is not a regular file: {resolved}")
    if not os.access(resolved, os.X_OK):
        raise ValueError(f"binary is not executable: {resolved}")
    return resolved


def checked_file(path: Path) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"package is not a regular file: {resolved}")
    return resolved


def benchmark_environment(config_home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    environment["NO_COLOR"] = "1"
    environment["XDG_CONFIG_HOME"] = str(config_home)
    for name in list(environment):
        if name.startswith("KICKOUTCHI_"):
            del environment[name]
    return environment


def evict_binary_pages(binary: Path) -> None:
    if not hasattr(os, "posix_fadvise") or not hasattr(os, "POSIX_FADV_DONTNEED"):
        raise RuntimeError("cold-start measurements require POSIX_FADV_DONTNEED")
    descriptor = os.open(binary, os.O_RDONLY)
    try:
        os.posix_fadvise(descriptor, 0, 0, os.POSIX_FADV_DONTNEED)
    finally:
        os.close(descriptor)


def run_once(
    binary: Path,
    arguments: Sequence[str],
    environment: dict[str, str],
    *,
    timeout_seconds: float,
    evict_binary: bool,
) -> Measurement:
    if evict_binary:
        evict_binary_pages(binary)

    devnull = os.open(os.devnull, os.O_RDWR)
    file_actions = [
        (os.POSIX_SPAWN_DUP2, devnull, 1),
        (os.POSIX_SPAWN_DUP2, devnull, 2),
        (os.POSIX_SPAWN_CLOSE, devnull),
    ]
    command = [str(binary), *arguments]
    started = time.perf_counter_ns()
    try:
        pid = os.posix_spawn(str(binary), command, environment, file_actions=file_actions)
    finally:
        os.close(devnull)

    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    while True:
        waited_pid, status, usage = os.wait4(pid, os.WNOHANG)
        if waited_pid == pid:
            break
        if time.monotonic() >= deadline:
            os.kill(pid, signal.SIGKILL)
            _, status, usage = os.wait4(pid, 0)
            timed_out = True
            break
        time.sleep(POLL_SECONDS)

    wall_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    return Measurement(
        wall_ms=wall_ms,
        user_ms=usage.ru_utime * 1_000.0,
        system_ms=usage.ru_stime * 1_000.0,
        max_rss_kib=int(usage.ru_maxrss),
        exit_code=os.waitstatus_to_exitcode(status),
        timed_out=timed_out,
    )


def bounded_correctness_run(
    binary: Path,
    arguments: Sequence[str],
    environment: dict[str, str],
    timeout_seconds: float,
) -> bytes:
    completed = subprocess.run(
        [str(binary), *arguments],
        check=False,
        capture_output=True,
        env=environment,
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        stderr = completed.stderr[:4_096].decode("utf-8", errors="replace")
        raise RuntimeError(
            f"{binary.name} {' '.join(arguments)} exited "
            f"{completed.returncode}: {stderr}"
        )
    if len(completed.stdout) > CORRECTNESS_OUTPUT_BYTES_MAX:
        raise RuntimeError(
            f"{binary.name} {' '.join(arguments)} exceeded the correctness-output bound"
        )
    return completed.stdout


def verify_correctness(
    binary: Path, environment: dict[str, str], timeout_seconds: float
) -> dict[str, object]:
    version = bounded_correctness_run(
        binary, ("--version",), environment, timeout_seconds
    )
    human = bounded_correctness_run(binary, ("list",), environment, timeout_seconds)
    structured = bounded_correctness_run(
        binary, ("list", "--json"), environment, timeout_seconds
    )
    try:
        parsed = json.loads(structured)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{binary.name} list --json emitted invalid JSON") from error
    return {
        "version": version.decode("utf-8", errors="strict").strip(),
        "list_bytes": len(human),
        "list_json_bytes": len(structured),
        "list_json_top_level": type(parsed).__name__,
    }


def measure_case(
    case: Case,
    binaries: dict[str, Path],
    environment: dict[str, str],
    *,
    warmups: int,
    timeout_seconds: float,
    randomizer: random.Random,
) -> dict[str, list[Measurement]]:
    labels = list(binaries)
    if not case.evict_binary:
        for _ in range(warmups):
            randomizer.shuffle(labels)
            for label in labels:
                warmup = run_once(
                    binaries[label],
                    case.arguments,
                    environment,
                    timeout_seconds=timeout_seconds,
                    evict_binary=False,
                )
                if warmup.exit_code != 0 or warmup.timed_out:
                    raise RuntimeError(f"{case.name} warmup failed for {label}")

    measurements: dict[str, list[Measurement]] = {label: [] for label in labels}
    for _ in range(case.samples):
        randomizer.shuffle(labels)
        for label in labels:
            measurements[label].append(
                run_once(
                    binaries[label],
                    case.arguments,
                    environment,
                    timeout_seconds=timeout_seconds,
                    evict_binary=case.evict_binary,
                )
            )
    return measurements


def metric_summary(measurements: Sequence[Measurement]) -> dict[str, float | int]:
    wall = [measurement.wall_ms for measurement in measurements]
    cpu = [
        measurement.user_ms + measurement.system_ms
        for measurement in measurements
    ]
    rss = [measurement.max_rss_kib for measurement in measurements]
    errors = sum(
        measurement.exit_code != 0 or measurement.timed_out
        for measurement in measurements
    )
    return {
        "wall_p50_ms": percentile(wall, 0.50),
        "wall_p95_ms": percentile(wall, 0.95),
        "wall_p99_ms": percentile(wall, 0.99),
        "cpu_p50_ms": percentile(cpu, 0.50),
        "rss_p50_kib": percentile(rss, 0.50),
        "rss_p95_kib": percentile(rss, 0.95),
        "errors": errors,
        "error_rate": errors / len(measurements),
    }


def machine_metadata() -> dict[str, object]:
    cpu_model = "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("model name") and ":" in line:
                cpu_model = line.split(":", maxsplit=1)[1].strip()
                break
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_model": cpu_model,
        "logical_cpus": os.cpu_count(),
        "load_average": list(os.getloadavg()),
    }


def markdown_report(result: dict[str, object]) -> str:
    labels = result["labels"]
    if not isinstance(labels, dict):
        raise TypeError("labels must be a mapping")
    baseline = str(labels["baseline"])
    candidate = str(labels["candidate"])
    lines = [
        "# Kickoutchi performance comparison",
        "",
        f"- Baseline: `{baseline}`",
        f"- Candidate: `{candidate}`",
        f"- Fixed interleaving seed: `{result['seed']}`",
        "- Cold startup: executable pages advised `DONTNEED` before each run; "
        "system-wide caches were not purged.",
        "- Significance: paired median change must exceed 5%, the case's absolute "
        "threshold, and three scaled median absolute deviations.",
        "",
        "| Case | Build | wall p50 | wall p95 | wall p99 | CPU p50 | RSS p50 | Errors |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    cases = result["cases"]
    if not isinstance(cases, dict):
        raise TypeError("cases must be a mapping")
    for case_name, case_value in cases.items():
        if not isinstance(case_value, dict):
            raise TypeError("case result must be a mapping")
        summaries = case_value["summaries"]
        if not isinstance(summaries, dict):
            raise TypeError("summaries must be a mapping")
        for label in [baseline, candidate]:
            summary = summaries[label]
            lines.append(
                f"| {case_name} | {label} | "
                f"{summary['wall_p50_ms']:.3f} ms | "
                f"{summary['wall_p95_ms']:.3f} ms | "
                f"{summary['wall_p99_ms']:.3f} ms | "
                f"{summary['cpu_p50_ms']:.3f} ms | "
                f"{summary['rss_p50_kib']:.0f} KiB | "
                f"{summary['errors']} |"
            )
    lines.extend(
        [
            "",
            "| Case | Candidate median delta | Required delta | Verdict |",
            "| --- | ---: | ---: | --- |",
        ]
    )
    for case_name, case_value in cases.items():
        lines.append(
            f"| {case_name} | {case_value['delta_ms']:+.3f} ms | "
            f"{case_value['required_delta_ms']:.3f} ms | "
            f"{case_value['verdict']} |"
        )

    sizes = result["sizes"]
    if not isinstance(sizes, dict):
        raise TypeError("sizes must be a mapping")
    lines.extend(
        [
            "",
            "| Artifact | Baseline | Candidate | Delta |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for artifact, values in sizes.items():
        baseline_size = values["baseline_bytes"]
        candidate_size = values["candidate_bytes"]
        delta = candidate_size - baseline_size
        percent = (delta / baseline_size * 100.0) if baseline_size else 0.0
        lines.append(
            f"| {artifact} | {baseline_size} B | {candidate_size} B | "
            f"{delta:+d} B ({percent:+.2f}%) |"
        )

    verdicts = [case["verdict"] for case in cases.values()]
    overall = "regression detected" if "regression" in verdicts else "no meaningful regression"
    lines.extend(["", f"Overall measured verdict: **{overall}**.", ""])
    return "\n".join(lines)


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--baseline", required=True, type=Path)
    argument_parser.add_argument("--candidate", required=True, type=Path)
    argument_parser.add_argument("--baseline-label", default="v1.3.8")
    argument_parser.add_argument("--candidate-label", required=True)
    argument_parser.add_argument(
        "--samples",
        default=50,
        type=lambda raw: bounded_integer(raw, SAMPLES_MIN, SAMPLES_MAX, "samples"),
    )
    argument_parser.add_argument(
        "--cold-samples",
        default=20,
        type=lambda raw: bounded_integer(
            raw, SAMPLES_MIN, SAMPLES_MAX, "cold samples"
        ),
    )
    argument_parser.add_argument(
        "--warmups",
        default=5,
        type=lambda raw: bounded_integer(raw, 0, WARMUPS_MAX, "warmups"),
    )
    argument_parser.add_argument(
        "--timeout-seconds",
        default=10.0,
        type=lambda raw: bounded_float(
            raw, 0.1, TIMEOUT_SECONDS_MAX, "timeout seconds"
        ),
    )
    argument_parser.add_argument("--seed", default=SEED_DEFAULT, type=int)
    argument_parser.add_argument("--baseline-package", type=Path)
    argument_parser.add_argument("--candidate-package", type=Path)
    argument_parser.add_argument("--json-output", type=Path)
    argument_parser.add_argument("--markdown-output", type=Path)
    return argument_parser


def main(arguments: Sequence[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    if sys.platform != "linux":
        raise RuntimeError("the benchmark harness currently supports Linux only")
    if (options.baseline_package is None) != (options.candidate_package is None):
        raise ValueError("baseline and candidate packages must be provided together")
    if options.baseline_label == options.candidate_label:
        raise ValueError("baseline and candidate labels must differ")

    binaries = {
        options.baseline_label: checked_binary(options.baseline),
        options.candidate_label: checked_binary(options.candidate),
    }
    packages = None
    if options.baseline_package is not None:
        packages = {
            "baseline": checked_file(options.baseline_package),
            "candidate": checked_file(options.candidate_package),
        }

    cases = [
        Case(
            "cold_start",
            ("--version",),
            True,
            options.cold_samples,
            0.25,
        ),
        Case("warm_start", ("--version",), False, options.samples, 0.25),
        Case("list", ("list",), False, options.samples, 0.50),
        Case("list_json", ("list", "--json"), False, options.samples, 0.50),
    ]
    randomizer = random.Random(options.seed)

    with tempfile.TemporaryDirectory(prefix="kickoutchi-benchmark-config-") as config:
        environment = benchmark_environment(Path(config))
        correctness = {
            label: verify_correctness(
                binary, environment, options.timeout_seconds
            )
            for label, binary in binaries.items()
        }
        case_results: dict[str, object] = {}
        for case in cases:
            measurements = measure_case(
                case,
                binaries,
                environment,
                warmups=options.warmups,
                timeout_seconds=options.timeout_seconds,
                randomizer=randomizer,
            )
            baseline_runs = measurements[options.baseline_label]
            candidate_runs = measurements[options.candidate_label]
            verdict, delta_ms, required_delta_ms = classify_wall_change(
                [measurement.wall_ms for measurement in baseline_runs],
                [measurement.wall_ms for measurement in candidate_runs],
                absolute_threshold_ms=case.absolute_threshold_ms,
            )
            case_results[case.name] = {
                "arguments": list(case.arguments),
                "evict_binary": case.evict_binary,
                "samples_per_build": case.samples,
                "summaries": {
                    label: metric_summary(runs)
                    for label, runs in measurements.items()
                },
                "delta_ms": delta_ms,
                "required_delta_ms": required_delta_ms,
                "verdict": verdict,
                "measurements": {
                    label: [measurement.to_dict() for measurement in runs]
                    for label, runs in measurements.items()
                },
            }

    sizes: dict[str, dict[str, int]] = {
        "kickoutchi binary": {
            "baseline_bytes": binaries[options.baseline_label].stat().st_size,
            "candidate_bytes": binaries[options.candidate_label].stat().st_size,
        }
    }
    if packages is not None:
        sizes["release package"] = {
            "baseline_bytes": packages["baseline"].stat().st_size,
            "candidate_bytes": packages["candidate"].stat().st_size,
        }

    result: dict[str, object] = {
        "schema_version": 1,
        "created_unix_seconds": int(time.time()),
        "labels": {
            "baseline": options.baseline_label,
            "candidate": options.candidate_label,
        },
        "paths": {label: str(path) for label, path in binaries.items()},
        "seed": options.seed,
        "warmups": options.warmups,
        "timeout_seconds": options.timeout_seconds,
        "machine": machine_metadata(),
        "correctness": correctness,
        "cases": case_results,
        "sizes": sizes,
    }
    report = markdown_report(result)
    print(report, end="")
    if options.json_output is not None:
        options.json_output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if options.markdown_output is not None:
        options.markdown_output.write_text(report, encoding="utf-8")

    errors = sum(
        summary["errors"]
        for case in case_results.values()
        for summary in case["summaries"].values()
    )
    return 2 if errors else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
