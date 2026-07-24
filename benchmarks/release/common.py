#!/usr/bin/env python3
import hashlib
import json
import math
import os
import stat
from pathlib import Path
from typing import Any

PLAN_BYTES_MAX = 1024 * 1024
RAW_BYTES_MAX = 512 * 1024 * 1024
MANIFEST_BYTES_MAX = 16 * 1024 * 1024
ARTIFACT_BYTES_MAX = 256 * 1024 * 1024
MAX_BLOCKS = 100
MAX_SAMPLES_PER_BLOCK = 10_000
MAX_WARMUPS = 100
MAX_TOTAL_ROWS = 500_000
MAX_HELPER_SOCKETS = 1024

REQUIRED_WORKLOADS = {
    "list_empty", "list_typical", "list_high", "startup_list_cold", "startup_list_warm",
    "snapshot_empty", "snapshot_typical", "snapshot_high", "snapshot_large", "snapshot_maximum",
    "diff_empty", "diff_typical", "diff_large", "diff_maximum_same", "diff_maximum_replacement",
    "why_full_matrix", "watch_stable", "watch_high_churn", "watch_transient_recovery",
    "watch_failure_exhaustion",
}
REQUIRED_SIGNATURES = {
    "list_empty": ("list", "namespace_fixture", "baseline_candidate", "warm", "fast_process"),
    "list_typical": ("list", "native_cli", "baseline_candidate", "warm", "fast_process"),
    "list_high": ("list", "native_cli", "baseline_candidate", "warm", "fast_process"),
    "startup_list_cold": ("startup", "native_cli", "baseline_candidate", "cold", "fast_process"),
    "startup_list_warm": ("startup", "native_cli", "baseline_candidate", "warm", "fast_process"),
    "snapshot_empty": ("snapshot", "namespace_fixture", "candidate_only", "warm", "fast_process"),
    "snapshot_typical": ("snapshot", "native_cli", "candidate_only", "warm", "fast_process"),
    "snapshot_high": ("snapshot", "native_cli", "candidate_only", "warm", "fast_process"),
    "snapshot_large": ("snapshot", "watch_fixture", "candidate_only", "not_applicable", "heavy_operation"),
    "snapshot_maximum": ("snapshot", "watch_fixture", "candidate_only", "not_applicable", "heavy_operation"),
    "diff_empty": ("diff", "diff_helper", "candidate_only", "not_applicable", "fast_process"),
    "diff_typical": ("diff", "diff_helper", "candidate_only", "not_applicable", "fast_process"),
    "diff_large": ("diff", "diff_helper", "candidate_only", "not_applicable", "heavy_operation"),
    "diff_maximum_same": ("diff", "diff_helper", "candidate_only", "not_applicable", "heavy_operation"),
    "diff_maximum_replacement": ("diff", "diff_helper", "candidate_only", "not_applicable", "heavy_operation"),
    "why_full_matrix": ("why", "native_cli", "candidate_only", "warm", "fast_process"),
    "watch_stable": ("watch", "native_cli", "candidate_only", "warm", "long_process"),
    "watch_high_churn": ("watch", "watch_fixture", "candidate_only", "warm", "long_process"),
    "watch_transient_recovery": ("watch", "watch_fixture", "candidate_only", "warm", "long_process"),
    "watch_failure_exhaustion": ("watch", "watch_fixture", "candidate_only", "warm", "long_process"),
}
REQUIRED_FIXTURES = {
    "list_empty": (0, 0, []), "list_typical": (64, 0, []), "list_high": (1024, 0, []),
    "startup_list_cold": (0, 0, []), "startup_list_warm": (0, 0, []),
    "snapshot_empty": (0, 0, []), "snapshot_typical": (64, 0, []), "snapshot_high": (1024, 0, []),
    "snapshot_large": (65_536, 0, []), "snapshot_maximum": (262_144, 0, []),
    "diff_empty": (0, 0, []), "diff_typical": (1024, 1024, []), "diff_large": (65_536, 65_536, []),
    "diff_maximum_same": (262_144, 0, []), "diff_maximum_replacement": (262_144, 524_288, []),
    "why_full_matrix": (0, 0, []), "watch_stable": (1, 0, []), "watch_high_churn": (1024, 2048, []),
    "watch_transient_recovery": (1, 0, ["success", "failure", "success"]),
    "watch_failure_exhaustion": (1, 0, ["success", "failure", "failure", "failure"]),
}
REQUIRED_ISOLATED = REQUIRED_WORKLOADS
EXPECTED_SCHEMA_BY_KIND = {"list":"list/1", "startup":"list/1", "snapshot":"kickoutchi.snapshot/1", "diff":"kickoutchi.release_diff_helper/1", "why":"kickoutchi.why/1", "watch":"kickoutchi.watch_event/1"}
WORKLOAD_KEYS = {
    "name", "kind", "scenario", "driver", "implemented", "comparison", "startup",
    "sampling", "command", "fixture", "expected", "calibration", "budgets",
}
BUDGET_METRICS = {
    "latency_p50_ns", "latency_p95_ns", "latency_p99_ns", "latency_max_ns",
    "cpu_p50_ns", "peak_memory_bytes", "throughput_events_per_second",
    "throughput_rows_per_second", "poll_cpu_ns", "artifact_bytes",
}
IMPLEMENTED_DRIVERS = {"native_cli", "namespace_fixture", "diff_helper", "watch_fixture"}
ABSOLUTE_MAX_METRICS = BUDGET_METRICS - {"throughput_events_per_second", "throughput_rows_per_second"}
ABSOLUTE_MIN_METRICS = {"throughput_events_per_second", "throughput_rows_per_second"}


class EvidenceError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_regular(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError(f"could not open {path}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"not a regular file: {path}")
        if metadata.st_size > maximum:
            raise EvidenceError(f"file exceeds {maximum} bytes: {path}")
        chunks: list[bytes] = []
        retained = 0
        while retained <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - retained))
            if not chunk:
                return b"".join(chunks)
            retained += len(chunk)
            chunks.append(chunk)
        raise EvidenceError(f"file exceeds {maximum} bytes: {path}")
    finally:
        os.close(descriptor)


def read_json(path: Path, maximum: int) -> tuple[Any, bytes]:
    contents = read_regular(path, maximum)
    try:
        return json.loads(contents), contents
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid JSON in {path}: {error}") from error


def require_absent(*paths: Path) -> None:
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise EvidenceError(f"could not inspect output {path}: {error}") from error
        raise EvidenceError(f"output already exists: {path}")


def _exact_keys(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{name} must be an object")
    actual = set(value)
    if actual != expected:
        raise EvidenceError(f"{name} keys differ: missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EvidenceError(f"{name} must be an integer in {minimum}..={maximum}")
    return value


def _number(value: Any, name: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise EvidenceError(f"{name} must be a finite number")
    if value < 0 or (positive and value <= 0):
        raise EvidenceError(f"{name} must be {'positive' if positive else 'nonnegative'}")
    return float(value)


def _sha(value: Any, name: str, *, required: bool = True) -> None:
    if value is None and not required:
        return
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise EvidenceError(f"{name} must be a lowercase SHA-256")


def _validate_budgets(value: Any, name: str) -> None:
    budgets = _exact_keys(value, {"failures_max", "absolute_max", "absolute_min", "relative_delta_percent_max"}, name)
    _integer(budgets["failures_max"], f"{name}.failures_max", 0, 1000)
    for group, allowed in (("absolute_max", ABSOLUTE_MAX_METRICS), ("absolute_min", ABSOLUTE_MIN_METRICS),
                           ("relative_delta_percent_max", BUDGET_METRICS)):
        values = budgets[group]
        if not isinstance(values, dict) or any(metric not in allowed for metric in values):
            raise EvidenceError(f"{name}.{group} contains an unknown or invalid metric")
        for metric, limit in values.items():
            _number(limit, f"{name}.{group}.{metric}")
    if not budgets["absolute_max"] and not budgets["absolute_min"]:
        raise EvidenceError(f"{name} must declare an absolute budget")


def _validate_calibration(value: Any, comparison: str, name: str) -> None:
    calibration = _exact_keys(value, {"mode", "metric_noise_limit_percent", "multiplier"}, name)
    expected = "baseline_aa" if comparison == "baseline_candidate" else "candidate_paired"
    if calibration["mode"] != expected:
        raise EvidenceError(f"{name}.mode must be {expected}")
    noise = calibration["metric_noise_limit_percent"]
    if not isinstance(noise, dict) or not noise or any(metric not in BUDGET_METRICS for metric in noise):
        raise EvidenceError(f"{name}.metric_noise_limit_percent is invalid")
    for metric, limit in noise.items():
        _number(limit, f"{name}.{metric}", positive=True)
    _number(calibration["multiplier"], f"{name}.multiplier", positive=True)


def _validate_workload(workload: Any, total_rows: int) -> int:
    item = _exact_keys(workload, WORKLOAD_KEYS, "workload")
    name = item["name"]
    if not isinstance(name, str) or name not in REQUIRED_WORKLOADS:
        raise EvidenceError(f"unknown workload name: {name!r}")
    if item["kind"] not in {"list", "startup", "snapshot", "diff", "why", "watch"}:
        raise EvidenceError(f"invalid workload kind for {name}")
    if item["driver"] not in {"native_cli", "namespace_fixture", "diff_helper", "watch_fixture"} or not isinstance(item["implemented"], bool):
        raise EvidenceError(f"invalid workload driver for {name}")
    comparison = item["comparison"]
    if comparison not in {"baseline_candidate", "candidate_only"}:
        raise EvidenceError(f"invalid comparison for {name}")
    if comparison == "baseline_candidate" and item["kind"] not in {"list", "startup"}:
        raise EvidenceError(f"unsupported baseline comparison for {name}")
    if item["startup"] not in {"cold", "warm", "not_applicable"}:
        raise EvidenceError(f"invalid startup semantics for {name}")
    sampling = _exact_keys(item["sampling"], {"profile", "blocks", "samples_per_block", "warmups"}, f"{name}.sampling")
    profile = sampling["profile"]
    if profile not in {"fast_process", "long_process", "heavy_operation"}:
        raise EvidenceError(f"invalid sampling profile for {name}")
    signature = (item["kind"], item["driver"], comparison, item["startup"], profile)
    if signature != REQUIRED_SIGNATURES[name]:
        raise EvidenceError(f"{name} workload signature differs from the required protocol")
    blocks = _integer(sampling["blocks"], f"{name}.blocks", 1, MAX_BLOCKS)
    samples = _integer(sampling["samples_per_block"], f"{name}.samples_per_block", 2, MAX_SAMPLES_PER_BLOCK)
    warmups = _integer(sampling["warmups"], f"{name}.warmups", 0, MAX_WARMUPS)
    if profile == "fast_process" and (blocks, samples, warmups) not in {(10, 1000, value) for value in range(10, 21)}:
        raise EvidenceError(f"{name} must use ten 1000-sample blocks and 10..20 warmups")
    if profile == "long_process" and not (blocks == 10 and 200 <= samples <= 500 and 10 <= warmups <= 20):
        raise EvidenceError(f"{name} must retain 2000..5000 process samples in ten blocks")
    if profile == "heavy_operation" and not (blocks >= 10 and samples >= 2 and 1 <= warmups <= 20):
        raise EvidenceError(f"{name} heavy-operation sampling is too small")
    if samples % 2:
        raise EvidenceError(f"{name} samples must be even for exact calibration balance")
    if not isinstance(item["command"], list) or not item["command"] or not all(isinstance(part, str) for part in item["command"]):
        raise EvidenceError(f"{name}.command must be a nonempty string array")
    _exact_keys(item["fixture"], {"socket_count", "churn_events", "failure_pattern", "isolated"}, f"{name}.fixture")
    socket_count = _integer(item["fixture"]["socket_count"], f"{name}.socket_count", 0, 262_144)
    _integer(item["fixture"]["churn_events"], f"{name}.churn_events", 0, 524_288)
    if not isinstance(item["fixture"]["failure_pattern"], list) or not all(value in {"success", "failure"} for value in item["fixture"]["failure_pattern"]):
        raise EvidenceError(f"{name}.failure_pattern is invalid")
    if not isinstance(item["fixture"]["isolated"], bool):
        raise EvidenceError(f"{name}.isolated must be boolean")
    fixture_signature = (socket_count, item["fixture"]["churn_events"], item["fixture"]["failure_pattern"])
    if fixture_signature != REQUIRED_FIXTURES[name] or item["fixture"]["isolated"] is not (name in REQUIRED_ISOLATED):
        raise EvidenceError(f"{name} fixture differs from the required protocol")
    if item["driver"] == "native_cli" and socket_count > MAX_HELPER_SOCKETS:
        raise EvidenceError(f"{name} native helper socket count exceeds {MAX_HELPER_SOCKETS}")
    expected = _exact_keys(item["expected"], {"schema", "rows", "events", "statuses", "stderr_empty"}, f"{name}.expected")
    if expected["schema"] not in {"list/1", "kickoutchi.snapshot/1", "kickoutchi.why/1", "kickoutchi.watch_event/1", "kickoutchi.release_diff_helper/1"}:
        raise EvidenceError(f"{name}.expected.schema is invalid")
    if expected["schema"] != EXPECTED_SCHEMA_BY_KIND[item["kind"]]:
        raise EvidenceError(f"{name}.expected.schema differs from its workload kind")
    for field, maximum in (("rows", 262_144), ("events", 524_288)):
        if expected[field] is not None:
            _integer(expected[field], f"{name}.expected.{field}", 0, maximum)
    if not isinstance(expected["statuses"], list) or not expected["statuses"] or not all(isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 255 for status in expected["statuses"]):
        raise EvidenceError(f"{name}.expected.statuses is invalid")
    if expected["stderr_empty"] is not True:
        raise EvidenceError(f"{name} must require empty stderr on valid output")
    list_rows = 0 if item["driver"] == "namespace_fixture" else None
    if item["kind"] in {"list", "startup"} and (expected["rows"] != list_rows or expected["events"] != 0 or expected["statuses"] != [0]):
        raise EvidenceError(f"{name} expected list result is invalid")
    if item["kind"] == "snapshot":
        required_rows = socket_count if item["driver"] in {"namespace_fixture", "watch_fixture"} else None
        if expected["rows"] != required_rows or expected["events"] != 0 or expected["statuses"] != [0]:
            raise EvidenceError(f"{name} expected snapshot result is invalid")
    if item["kind"] == "diff" and (expected["rows"] != socket_count or expected["events"] != item["fixture"]["churn_events"] or expected["statuses"] != [0]):
        raise EvidenceError(f"{name} expected diff result is invalid")
    if item["kind"] == "why" and (expected["rows"] != 8 or expected["events"] != 0 or expected["statuses"] != [0, 3]):
        raise EvidenceError(f"{name} expected Why matrix is invalid")
    if item["kind"] == "watch":
        watch_events = {"watch_stable":1, "watch_high_churn":3072, "watch_transient_recovery":2, "watch_failure_exhaustion":4}[name]
        watch_statuses = [0]
        if expected["rows"] != 0 or expected["events"] != watch_events or expected["statuses"] != watch_statuses:
            raise EvidenceError(f"{name} expected watch result is invalid")
    _validate_calibration(item["calibration"], comparison, f"{name}.calibration")
    _validate_budgets(item["budgets"], f"{name}.budgets")
    lanes = 4 if comparison == "baseline_candidate" else 1
    return total_rows + blocks * samples * lanes


def validate_plan(plan: Any, *, require_gate_ready: bool = True) -> dict[str, Any]:
    top = _exact_keys(plan, {
        "schema", "version", "immutable", "gate_mode", "gate_ready", "decision", "ordering_seed",
        "protocol_identity", "artifacts", "bounds", "stop_cleanup_rules", "environment_requirements",
        "artifact_budgets", "workloads",
    }, "plan")
    if top["schema"] != "kickoutchi.release_benchmark_plan" or top["version"] != 2:
        raise EvidenceError("plan must be kickoutchi.release_benchmark_plan/2")
    if top["immutable"] is not True or top["gate_mode"] != "final" or not isinstance(top["gate_ready"], bool):
        raise EvidenceError("plan immutable, gate mode, or readiness is invalid")
    _integer(top["ordering_seed"], "ordering_seed", 0, (1 << 63) - 1)
    identity = _exact_keys(top["protocol_identity"], {"harness_commit", "harness_tree_sha256", "included_product_sources_sha256", "diff_helper_source_sha256", "diff_helper_lock_sha256", "diff_helper_sha256_by_platform", "rust_target_by_platform", "rustc_version"}, "protocol_identity")
    for key in ("harness_tree_sha256", "included_product_sources_sha256", "diff_helper_source_sha256", "diff_helper_lock_sha256"):
        _sha(identity[key], f"protocol_identity.{key}", required=False)
    helper_hashes = identity["diff_helper_sha256_by_platform"]
    if helper_hashes is not None:
        if not isinstance(helper_hashes, dict):
            raise EvidenceError("protocol_identity.diff_helper_sha256_by_platform is invalid")
        for platform_key, digest in helper_hashes.items():
            if not isinstance(platform_key, str):
                raise EvidenceError("diff helper platform key is invalid")
            _sha(digest, f"diff_helper.{platform_key}")
    targets = identity["rust_target_by_platform"]
    if targets is not None and (not isinstance(targets, dict) or not targets or not all(isinstance(key, str) and isinstance(value, str) and value for key, value in targets.items())):
        raise EvidenceError("protocol_identity.rust_target_by_platform is invalid")
    for key in ("harness_commit", "rustc_version"):
        if identity[key] is not None and (not isinstance(identity[key], str) or not identity[key]):
            raise EvidenceError(f"protocol_identity.{key} is invalid")
    if identity["harness_commit"] is not None and len(identity["harness_commit"]) != 40:
        raise EvidenceError("protocol_identity.harness_commit must be a full Git object ID")
    artifacts = _exact_keys(top["artifacts"], {"baseline", "candidate"}, "artifacts")
    for role, version in (("baseline", "1.2.0"), ("candidate", "1.3.0")):
        artifact = _exact_keys(artifacts[role], {"version", "source", "source_commit", "sha256_by_platform"}, f"artifacts.{role}")
        if artifact["version"] != version or not isinstance(artifact["source"], str):
            raise EvidenceError(f"{role} artifact identity is invalid")
        if role == "candidate" and (not isinstance(artifact["source_commit"], str) or len(artifact["source_commit"]) != 40):
            raise EvidenceError("candidate source_commit must be a full Git object ID")
        if role == "baseline" and artifact["source_commit"] is not None:
            raise EvidenceError("baseline source_commit must be null for the published artifact")
        hashes = artifact["sha256_by_platform"]
        if not isinstance(hashes, dict):
            raise EvidenceError(f"{role} sha256_by_platform must be an object")
        for platform_key, digest in hashes.items():
            if not isinstance(platform_key, str):
                raise EvidenceError(f"{role} platform key is invalid")
            _sha(digest, f"{role}.{platform_key}")
    bounds = _exact_keys(top["bounds"], {"artifact_bytes_max", "retained_output_bytes_max", "stream_bytes_max", "child_timeout_seconds", "run_timeout_seconds", "max_failures"}, "bounds")
    _integer(bounds["artifact_bytes_max"], "artifact_bytes_max", 1, ARTIFACT_BYTES_MAX)
    _integer(bounds["retained_output_bytes_max"], "retained_output_bytes_max", 1024, 64 * 1024 * 1024)
    _integer(bounds["stream_bytes_max"], "stream_bytes_max", bounds["retained_output_bytes_max"], 1 << 40)
    _integer(bounds["child_timeout_seconds"], "child_timeout_seconds", 1, 120)
    _integer(bounds["run_timeout_seconds"], "run_timeout_seconds", 1, 6 * 60 * 60)
    _integer(bounds["max_failures"], "max_failures", 1, 1000)
    cleanup = _exact_keys(top["stop_cleanup_rules"], {"process_tree", "bounded_stream_readers", "close_helpers", "exclusive_publish"}, "stop_cleanup_rules")
    if cleanup != {"process_tree": True, "bounded_stream_readers": True, "close_helpers": True, "exclusive_publish": True}:
        raise EvidenceError("all cleanup rules must be enabled")
    environment = _exact_keys(top["environment_requirements"], {"compiler", "target", "cpu", "ram", "os", "kernel", "power", "thermal", "concurrent_load"}, "environment_requirements")
    if set(environment.values()) != {True}:
        raise EvidenceError("all environment metadata requirements must be enabled")
    _validate_budgets(top["artifact_budgets"], "artifact_budgets")
    workloads = top["workloads"]
    if not isinstance(workloads, list):
        raise EvidenceError("workloads must be an array")
    names: set[str] = set()
    total_rows = 0
    for workload in workloads:
        total_rows = _validate_workload(workload, total_rows)
        if workload["name"] in names:
            raise EvidenceError(f"duplicate workload: {workload['name']}")
        names.add(workload["name"])
    if names != REQUIRED_WORKLOADS:
        raise EvidenceError(f"workload matrix differs: missing={sorted(REQUIRED_WORKLOADS - names)}, unknown={sorted(names - REQUIRED_WORKLOADS)}")
    if total_rows > MAX_TOTAL_ROWS:
        raise EvidenceError(f"planned rows exceed {MAX_TOTAL_ROWS}")
    if require_gate_ready:
        if top["gate_ready"] is not True:
            raise EvidenceError("plan is not ready for gate-eligible collection")
        if not all(workload["implemented"] for workload in workloads):
            raise EvidenceError("gate-ready plan contains an unimplemented workload")
        if any(workload["driver"] not in IMPLEMENTED_DRIVERS for workload in workloads):
            raise EvidenceError("gate-ready plan contains an unavailable workload driver")
        reproducible_identity = {key:value for key, value in identity.items() if key != "diff_helper_sha256_by_platform"}
        if any(value is None for value in reproducible_identity.values()):
            raise EvidenceError("gate-ready plan has incomplete protocol identity")
        for role in ("baseline", "candidate"):
            if not artifacts[role]["sha256_by_platform"]:
                raise EvidenceError(f"gate-ready plan has no {role} artifact hashes")
    return top


def balanced_orders(seed: int, workload: str, block: int, pairs: int) -> list[tuple[str, str]]:
    if pairs < 1:
        raise EvidenceError("balanced pair count must be positive")
    material = f"{seed}:{workload}:{block}".encode()
    ranked = sorted(range(pairs), key=lambda item: hashlib.sha256(material + b":" + str(item).encode()).digest())
    reversed_count = pairs // 2
    if pairs % 2 and hashlib.sha256(material).digest()[0] & 1:
        reversed_count += 1
    reversed_pairs = set(ranked[:reversed_count])
    return [("right", "left") if item in reversed_pairs else ("left", "right") for item in range(pairs)]


def nearest_rank(values: list[int], percent: int) -> int:
    if not values or not 1 <= percent <= 100:
        raise EvidenceError("percentile requires values and a percent in 1..=100")
    ordered = sorted(values)
    return ordered[(len(ordered) * percent + 99) // 100 - 1]
