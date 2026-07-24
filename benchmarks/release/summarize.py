#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any

if __package__:
    from .common import MANIFEST_BYTES_MAX, MAX_TOTAL_ROWS, PLAN_BYTES_MAX, RAW_BYTES_MAX, EvidenceError, balanced_orders, canonical_json, nearest_rank, read_json, read_regular, require_absent, sha256_bytes, validate_plan
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from benchmarks.release.common import MANIFEST_BYTES_MAX, MAX_TOTAL_ROWS, PLAN_BYTES_MAX, RAW_BYTES_MAX, EvidenceError, balanced_orders, canonical_json, nearest_rank, read_json, read_regular, require_absent, sha256_bytes, validate_plan

ROW_KEYS = {"schema", "version", "plan_sha256", "mode", "gate_eligible", "workload", "lane", "artifact_role", "lane_side", "executor_role", "executor_sha256", "executor_bytes", "block", "pair", "order", "sample", "command", "latency_ns", "operation_duration_ns", "scanned_count", "user_cpu_ns", "system_cpu_ns", "peak_memory_bytes", "status", "outcome", "error", "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256", "row_count", "event_count"}
MANIFEST_KEYS = {"schema", "version", "plan_sha256", "raw_sha256", "mode", "gate_eligible", "complete", "started_utc", "duration_ns", "source_commit", "harness_commit", "checkout_commit", "platform_key", "environment", "commands", "versions", "diff_helper_sha256", "diff_helper_bytes", "fixture_scope", "not_applicable_workloads", "artifacts", "row_count", "failure_count", "skipped_workloads", "notes"}


def delta_percent(baseline: int | float, candidate: int | float) -> float:
    if baseline <= 0:
        return 0.0 if candidate == baseline else math.inf
    return (candidate - baseline) * 100.0 / baseline


def distribution(rows: list[dict[str, Any]], polls_per_invocation: int | None = None) -> dict[str, Any]:
    valid = [row for row in rows if row["outcome"] == "valid"]
    latency = [row["latency_ns"] for row in valid]
    if not latency:
        return {"samples": 0, "failures": len(rows)}
    block_p99 = [nearest_rank([row["latency_ns"] for row in valid if row["block"] == block], 99) for block in sorted({row["block"] for row in valid})]
    cpu = [row["user_cpu_ns"] + row["system_cpu_ns"] for row in valid if row["user_cpu_ns"] is not None and row["system_cpu_ns"] is not None]
    memory = [row["peak_memory_bytes"] for row in valid if row["peak_memory_bytes"] is not None]
    total_latency = sum(latency)
    operation_durations = [row["operation_duration_ns"] for row in valid if row["operation_duration_ns"] is not None]
    total_operation_duration = sum(operation_durations) if operation_durations else total_latency
    total_rows = sum(row["scanned_count"] if row["scanned_count"] is not None else row["row_count"] for row in valid)
    total_events = sum(row["event_count"] for row in valid)
    failures: dict[str, int] = {}
    for row in rows:
        if row["outcome"] != "valid":
            key = row["error"] or f"status_{row['status']}"
            failures[key] = failures.get(key, 0) + 1
    return {"samples": len(valid), "failures": len(rows) - len(valid), "failure_reasons": failures,
            "latency_p50_ns": nearest_rank(latency, 50), "latency_p95_ns": nearest_rank(latency, 95), "latency_p99_ns": nearest_rank(latency, 99), "latency_max_ns": max(latency),
            "block_p99_min_ns": min(block_p99), "block_p99_max_ns": max(block_p99),
            "cpu_p50_ns": nearest_rank(cpu, 50) if cpu else None, "peak_memory_bytes": max(memory) if memory else None,
            "poll_cpu_ns": nearest_rank(cpu, 50) / polls_per_invocation if cpu and polls_per_invocation else None,
            "throughput_events_per_second": total_events * 1_000_000_000 / total_operation_duration,
            "throughput_rows_per_second": total_rows * 1_000_000_000 / total_operation_duration,
            "measurement_duration_ns": total_latency, "operation_duration_ns": sum(operation_durations) if operation_durations else None,
            "row_count_min": min(row["row_count"] for row in valid), "row_count_max": max(row["row_count"] for row in valid),
            "event_count_min": min(row["event_count"] for row in valid), "event_count_max": max(row["event_count"] for row in valid)}


def metric_noise(left: dict[str, Any], right: dict[str, Any], metrics: dict[str, float]) -> dict[str, float | None]:
    result: dict[str, float | None] = {}
    for metric in metrics:
        if left.get(metric) is None or right.get(metric) is None:
            result[metric] = None
        else:
            result[metric] = abs(delta_percent(left[metric], right[metric]))
    return result


def classify(budgets: dict[str, Any], baseline: dict[str, Any] | None, candidate: dict[str, Any], noise: dict[str, float | None], calibration: dict[str, Any]) -> tuple[str, list[str], dict[str, float]]:
    reasons: list[str] = []
    deltas: dict[str, float] = {}
    if candidate.get("failures", 0) > budgets["failures_max"] or (baseline and baseline.get("failures", 0) > budgets["failures_max"]):
        return "FAIL", ["validated invocation failures exceed the absolute budget"], deltas
    for metric, limit in budgets["absolute_max"].items():
        value = candidate.get(metric)
        if value is None:
            reasons.append(f"required absolute metric {metric} is unavailable")
        elif value > limit:
            reasons.append(f"{metric}={value} exceeds absolute maximum {limit}")
            return "FAIL", reasons, deltas
    for metric, limit in budgets["absolute_min"].items():
        value = candidate.get(metric)
        if value is None:
            reasons.append(f"required absolute metric {metric} is unavailable")
        elif value < limit:
            reasons.append(f"{metric}={value} is below absolute minimum {limit}")
            return "FAIL", reasons, deltas
    verdict = "INCONCLUSIVE" if reasons else "PASS"
    if baseline is not None:
        for metric, limit in budgets["relative_delta_percent_max"].items():
            if baseline.get(metric) is None or candidate.get(metric) is None:
                verdict = "INCONCLUSIVE"
                reasons.append(f"relative metric {metric} is unavailable")
                continue
            delta = delta_percent(baseline[metric], candidate[metric])
            deltas[metric] = delta
            if delta > limit:
                measured_noise = noise.get(metric)
                if measured_noise is not None and delta > measured_noise * calibration["multiplier"]:
                    verdict = "FAIL"
                    reasons.append(f"{metric} regression {delta:.3f}% exceeds budget {limit:.3f}% and metric noise")
                elif verdict != "FAIL":
                    verdict = "INCONCLUSIVE"
                    reasons.append(f"{metric} crosses its budget within measured uncertainty")
    relevant = set(budgets["absolute_max"]) | set(budgets["absolute_min"]) | set(budgets["relative_delta_percent_max"])
    for metric in relevant & set(calibration["metric_noise_limit_percent"]):
        measured = noise.get(metric)
        if measured is None:
            if verdict != "FAIL":
                verdict = "INCONCLUSIVE"
            reasons.append(f"calibration metric {metric} is unavailable")
        elif measured > calibration["metric_noise_limit_percent"][metric] and verdict != "FAIL":
            verdict = "INCONCLUSIVE"
            reasons.append(f"{metric} calibration noise {measured:.3f}% exceeds its declared limit")
    return verdict, reasons, deltas


def _integer(value: Any, name: str, maximum: int, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EvidenceError(f"invalid observation {name}")
    return value


def _sha(value: Any, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise EvidenceError(f"invalid observation {name}")


def parse_rows(raw: bytes, plan_hash: str) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line:
            raise EvidenceError(f"empty JSONL record at line {line_number}")
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EvidenceError(f"malformed JSONL at line {line_number}: {error}") from error
        if not isinstance(row, dict) or set(row) != ROW_KEYS or row.get("schema") != "kickoutchi.release_observation" or row.get("version") != 2:
            raise EvidenceError(f"invalid observation schema or keys at line {line_number}")
        if row["plan_sha256"] != plan_hash or row["mode"] not in {"final", "smoke"} or row["gate_eligible"] is not (row["mode"] == "final"):
            raise EvidenceError(f"observation identity mismatch at line {line_number}")
        for key, maximum in (("latency_ns", 120_000_000_000), ("status", 255), ("stdout_bytes", 1 << 40), ("stderr_bytes", 1 << 40), ("row_count", 262_144), ("event_count", 524_288), ("executor_bytes", 256 * 1024 * 1024)):
            _integer(row[key], key, maximum)
        for key, maximum in (("block", 100), ("pair", 10_000), ("order", 2), ("sample", 500_000)):
            _integer(row[key], key, maximum, positive=True)
        for key in ("operation_duration_ns", "scanned_count", "user_cpu_ns", "system_cpu_ns", "peak_memory_bytes"):
            if row[key] is not None:
                _integer(row[key], key, 1 << 50)
        if row["outcome"] not in {"valid", "error"} or row["artifact_role"] not in {"baseline", "candidate"} or row["executor_role"] not in {"baseline", "candidate", "source_helper"} or row["lane"] not in {"calibration", "comparison"} or row["lane_side"] not in {"left", "right"}:
            raise EvidenceError(f"invalid observation classification at line {line_number}")
        if row["error"] is not None and not isinstance(row["error"], str):
            raise EvidenceError(f"invalid observation error at line {line_number}")
        if not isinstance(row["command"], list) or not all(isinstance(value, str) for value in row["command"]):
            raise EvidenceError(f"invalid observation command at line {line_number}")
        for key in ("executor_sha256", "stdout_sha256", "stderr_sha256"):
            _sha(row[key], key)
        if row["outcome"] == "valid" and row["stderr_bytes"] != 0:
            raise EvidenceError(f"valid observation has stderr at line {line_number}")
        rows.append(row)
        if len(rows) > MAX_TOTAL_ROWS:
            raise EvidenceError(f"observation count exceeds {MAX_TOTAL_ROWS}")
    return rows


def validate_manifest(plan: dict[str, Any], manifest: dict[str, Any]) -> None:
    if set(manifest) != MANIFEST_KEYS or manifest.get("schema") != "kickoutchi.release_benchmark_manifest" or manifest.get("version") != 2 or manifest.get("complete") is not True:
        raise EvidenceError("manifest schema or exact keys are invalid")
    mode = manifest["mode"]
    if mode not in {"final", "smoke"} or manifest["gate_eligible"] is not (mode == "final"):
        raise EvidenceError("manifest mode and gate eligibility differ")
    checkout_commit = manifest["checkout_commit"]
    if manifest["source_commit"] != plan["artifacts"]["candidate"]["source_commit"] or not isinstance(checkout_commit, str) or len(checkout_commit) != 40 or any(character not in "0123456789abcdef" for character in checkout_commit):
        raise EvidenceError("manifest source identity is invalid")
    if manifest["harness_commit"] != plan["protocol_identity"]["harness_commit"] or (mode == "final" and (not isinstance(manifest["harness_commit"], str) or len(manifest["harness_commit"]) != 40)):
        raise EvidenceError("manifest harness commit differs from the plan")
    for key in ("plan_sha256", "raw_sha256"):
        _sha(manifest[key], key)
    _integer(manifest["duration_ns"], "duration_ns", plan["bounds"]["run_timeout_seconds"] * 1_000_000_000)
    try:
        started = dt.datetime.fromisoformat(manifest["started_utc"])
    except (TypeError, ValueError) as error:
        raise EvidenceError("manifest started_utc is invalid") from error
    if started.tzinfo is None or started.utcoffset() != dt.timedelta(0):
        raise EvidenceError("manifest started_utc must be UTC")
    if manifest["versions"] != {"baseline":"kickoutchi 1.2.0","candidate":"kickoutchi 1.3.0"}:
        raise EvidenceError("manifest versions are invalid")
    if not isinstance(manifest["skipped_workloads"], list) or (mode == "final" and manifest["skipped_workloads"]):
        raise EvidenceError("final manifest cannot skip workloads")
    not_applicable = manifest["not_applicable_workloads"]
    expected_not_applicable = ["list_empty", "snapshot_empty"] if manifest["platform_key"] == "windows-amd64" else []
    if not_applicable != expected_not_applicable:
        raise EvidenceError("manifest platform applicability differs from the protocol")
    fixture_scope = manifest["fixture_scope"]
    if not isinstance(fixture_scope, dict) or set(fixture_scope) != {"kind", "method", "parent_identifier", "identifier", "initial_rows"}:
        raise EvidenceError("manifest fixture scope is invalid")
    if manifest["platform_key"] == "linux-x86_64":
        namespace_pattern = re.compile(r"net:\[[1-9][0-9]*\]")
        if fixture_scope["kind"] != "linux_network_namespace" or fixture_scope["method"] != "unshare" or not isinstance(fixture_scope["parent_identifier"], str) or not isinstance(fixture_scope["identifier"], str) or namespace_pattern.fullmatch(fixture_scope["parent_identifier"]) is None or namespace_pattern.fullmatch(fixture_scope["identifier"]) is None or fixture_scope["parent_identifier"] == fixture_scope["identifier"] or fixture_scope["initial_rows"] != {"tcp":0,"tcp6":0,"udp":0,"udp6":0}:
            raise EvidenceError("Linux fixture scope is not a verified empty namespace")
    elif fixture_scope != {"kind":"native_host_stack","method":"none","parent_identifier":None,"identifier":None,"initial_rows":{}}:
        raise EvidenceError("non-Linux fixture scope is invalid")
    environment = manifest["environment"]
    required_environment = {"compiler", "target", "cpu", "cpu_count", "ram_bytes", "os", "kernel", "power", "thermal", "concurrent_load", "python"}
    if not isinstance(environment, dict) or set(environment) != required_environment:
        raise EvidenceError("manifest environment metadata is incomplete")
    platform_key = manifest["platform_key"]
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"baseline", "candidate"}:
        raise EvidenceError("manifest artifact identities are invalid")
    for role in ("baseline", "candidate"):
        expected = plan["artifacts"][role]["sha256_by_platform"].get(platform_key)
        identity = artifacts[role]
        if not isinstance(identity, dict) or set(identity) != {"sha256", "bytes"} or not expected or identity["sha256"] != expected:
            raise EvidenceError(f"manifest {role} identity differs from the plan")
        _integer(identity["bytes"], f"{role} artifact bytes", 256 * 1024 * 1024, positive=True)
    if manifest["diff_helper_sha256"] is not None:
        _sha(manifest["diff_helper_sha256"], "diff_helper_sha256")
        _integer(manifest["diff_helper_bytes"], "diff_helper_bytes", 256 * 1024 * 1024, positive=True)
    elif manifest["diff_helper_bytes"] is not None:
        raise EvidenceError("manifest diff helper identity is incomplete")
    elif mode == "final":
        raise EvidenceError("final manifest has no exact-source diff helper identity")
    commands = manifest["commands"]
    if not isinstance(commands, dict):
        raise EvidenceError("manifest commands are invalid")
    for workload in plan["workloads"]:
        if workload["name"] in manifest["skipped_workloads"] or workload["name"] in not_applicable:
            continue
        command = commands.get(workload["name"])
        if not isinstance(command, list) or len(command) != len(workload["command"]):
            raise EvidenceError(f"manifest command is invalid for {workload['name']}")
        for actual, declared in zip(command, workload["command"]):
            if declared.startswith("{"):
                if not isinstance(actual, str) or not actual.isdecimal() or not 1 <= int(actual) <= 65535:
                    raise EvidenceError(f"manifest selected port is invalid for {workload['name']}")
            elif actual != declared:
                raise EvidenceError(f"manifest command differs for {workload['name']}")


def validate_order(plan: dict[str, Any], manifest: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    cursor = 0
    counts: dict[tuple[str, str, str, str], int] = {}
    skipped = set(manifest["skipped_workloads"]) | set(manifest["not_applicable_workloads"])
    for declared in plan["workloads"]:
        if declared["name"] in skipped:
            continue
        workload = declared
        sampling = dict(workload["sampling"])
        if manifest["mode"] == "smoke":
            sampling.update(blocks=1, samples_per_block=4, warmups=1)
        for block in range(1, sampling["blocks"] + 1):
            pair_count = sampling["samples_per_block"] if workload["comparison"] == "baseline_candidate" else sampling["samples_per_block"] // 2
            orders = balanced_orders(plan["ordering_seed"], workload["name"], block, pair_count)
            for pair, sides in enumerate(orders, 1):
                expected = []
                if workload["comparison"] == "baseline_candidate":
                    lanes = (("calibration", {"left":"baseline","right":"baseline"}), ("comparison", {"left":"baseline","right":"candidate"}))
                else:
                    lanes = (("calibration", {"left":"candidate","right":"candidate"}),)
                for lane_name, lane in lanes:
                    for position, side in enumerate(sides, 1):
                        expected.append((lane_name, lane[side], side, position))
                for lane, role, side, position in expected:
                    if cursor >= len(rows):
                        raise EvidenceError("raw observations end before the plan")
                    row = rows[cursor]
                    actual = (row["workload"], row["block"], row["pair"], row["lane"], row["artifact_role"], row["lane_side"], row["order"])
                    wanted = (workload["name"], block, pair, lane, role, side, position)
                    if actual != wanted:
                        raise EvidenceError(f"observation order mismatch at row {cursor + 1}")
                    key = (workload["name"], lane, role, side)
                    counts[key] = counts.get(key, 0) + 1
                    if row["sample"] != counts[key] or row["command"] != manifest["commands"][workload["name"]]:
                        raise EvidenceError(f"sample sequence or command mismatch at row {cursor + 1}")
                    if workload["driver"] in {"diff_helper", "watch_fixture"}:
                        if row["outcome"] == "valid" and row["operation_duration_ns"] is None:
                            raise EvidenceError(f"helper operation metrics are invalid at row {cursor + 1}")
                        if workload["driver"] == "diff_helper" and row["outcome"] == "valid" and row["scanned_count"] != workload["fixture"]["socket_count"] * 2:
                            raise EvidenceError(f"diff scan metrics are invalid at row {cursor + 1}")
                        if workload["driver"] == "watch_fixture" and row["scanned_count"] is not None:
                            raise EvidenceError(f"fixture scan metrics are invalid at row {cursor + 1}")
                    elif row["operation_duration_ns"] is not None or row["scanned_count"] is not None:
                        raise EvidenceError(f"non-diff operation metrics are present at row {cursor + 1}")
                    cursor += 1
    if cursor != len(rows):
        raise EvidenceError("raw observations continue beyond the plan")


def validate_row_artifacts(plan: dict[str, Any], manifest: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    workload_drivers = {workload["name"]:workload["driver"] for workload in plan["workloads"]}
    for index, row in enumerate(rows, 1):
        driver = workload_drivers.get(row["workload"])
        if driver is None:
            raise EvidenceError(f"unknown observation workload at row {index}")
        if driver in {"diff_helper", "watch_fixture"}:
            expected_hash, expected_bytes = manifest["diff_helper_sha256"], manifest["diff_helper_bytes"]
            expected_role = "source_helper"
        else:
            identity = manifest["artifacts"][row["artifact_role"]]
            expected_hash, expected_bytes = identity["sha256"], identity["bytes"]
            expected_role = row["artifact_role"]
        if row["executor_role"] != expected_role or row["executor_sha256"] != expected_hash or row["executor_bytes"] != expected_bytes:
            raise EvidenceError(f"observation artifact identity mismatch at row {index}")


def summarize(plan: dict[str, Any], manifest: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    reports = []
    overall = "PASS"
    skipped = set(manifest["skipped_workloads"])
    not_applicable = set(manifest["not_applicable_workloads"])
    for workload in plan["workloads"]:
        if workload["name"] in not_applicable:
            reports.append({"name":workload["name"],"verdict":"NOT_APPLICABLE","reasons":["no verified empty Windows network compartment"]})
            continue
        if workload["name"] in skipped:
            reports.append({"name":workload["name"],"verdict":"INCONCLUSIVE","reasons":["workload unavailable in smoke mode"]})
            overall = "INCONCLUSIVE"
            continue
        selected = [row for row in rows if row["workload"] == workload["name"]]
        polls = {"watch_stable":5,"watch_high_churn":2,"watch_transient_recovery":3,"watch_failure_exhaustion":4}.get(workload["name"])
        calibration_left = distribution([row for row in selected if row["lane"] == "calibration" and row["lane_side"] == "left"], polls)
        calibration_right = distribution([row for row in selected if row["lane"] == "calibration" and row["lane_side"] == "right"], polls)
        noise = metric_noise(calibration_left, calibration_right, workload["calibration"]["metric_noise_limit_percent"])
        if workload["comparison"] == "baseline_candidate":
            baseline = distribution([row for row in selected if row["lane"] == "comparison" and row["artifact_role"] == "baseline"], polls)
            candidate = distribution([row for row in selected if row["lane"] == "comparison" and row["artifact_role"] == "candidate"], polls)
        else:
            baseline = None
            candidate = distribution([row for row in selected if row["lane"] == "calibration"], polls)
        classification_budgets = workload["budgets"]
        if not manifest["gate_eligible"]:
            classification_budgets = dict(workload["budgets"], relative_delta_percent_max={})
        verdict, reasons, deltas = classify(classification_budgets, baseline, candidate, noise, workload["calibration"])
        report = {"name":workload["name"],"scenario":workload["scenario"],"comparison_supported":baseline is not None,"verdict":verdict,"reasons":reasons,
                  "executor_role":"source_helper" if workload["driver"] in {"diff_helper", "watch_fixture"} else "release_artifact","calibration":{"left":calibration_left,"right":calibration_right,"metric_absolute_delta_percent":noise},"candidate":candidate,"budgets":workload["budgets"],"deltas_percent":deltas}
        if baseline is not None:
            report["baseline"] = baseline
        reports.append(report)
        if verdict == "FAIL": overall = "FAIL"
        elif verdict == "INCONCLUSIVE" and overall != "FAIL": overall = "INCONCLUSIVE"
    artifacts = manifest["artifacts"]
    size_candidate = {"failures":0,"artifact_bytes":artifacts["candidate"]["bytes"]}
    size_baseline = {"failures":0,"artifact_bytes":artifacts["baseline"]["bytes"]}
    size_noise: dict[str, float | None] = {"artifact_bytes":0.0}
    size_calibration = {"metric_noise_limit_percent":{"artifact_bytes":0.01},"multiplier":1.0}
    size_verdict, size_reasons, size_deltas = classify(plan["artifact_budgets"], size_baseline, size_candidate, size_noise, size_calibration)
    if size_verdict == "FAIL": overall = "FAIL"
    if not manifest["gate_eligible"] and overall != "FAIL": overall = "INCONCLUSIVE"
    return {"schema":"kickoutchi.release_benchmark_summary","version":2,"verdict":overall,"gate_eligible":manifest["gate_eligible"],"mode":manifest["mode"],
            "plan_sha256":manifest["plan_sha256"],"raw_sha256":manifest["raw_sha256"],"artifacts":artifacts,
            "artifact_size":{"verdict":size_verdict,"reasons":size_reasons,"deltas_percent":size_deltas,"budgets":plan["artifact_budgets"]},
            "workloads":reports,"caveats":["Smoke mode is non-gate evidence and skipped integrations remain inconclusive."] if not manifest["gate_eligible"] else []}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and summarize native release evidence.")
    parser.add_argument("--plan", required=True, type=Path); parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path); parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        plan, plan_bytes = read_json(args.plan, PLAN_BYTES_MAX)
        manifest, _ = read_json(args.manifest, MANIFEST_BYTES_MAX)
        if not isinstance(manifest, dict): raise EvidenceError("manifest must be an object")
        validate_plan(plan, require_gate_ready=manifest.get("mode") != "smoke")
        validate_manifest(plan, manifest)
        raw = read_regular(args.raw, RAW_BYTES_MAX)
        require_absent(args.output.absolute())
        if manifest["plan_sha256"] != sha256_bytes(plan_bytes) or manifest["raw_sha256"] != sha256_bytes(raw):
            raise EvidenceError("plan or raw hash differs from the manifest")
        rows = parse_rows(raw, manifest["plan_sha256"])
        if manifest["row_count"] != len(rows) or manifest["failure_count"] != sum(row["outcome"] != "valid" for row in rows):
            raise EvidenceError("manifest row or failure count differs")
        if {row["mode"] for row in rows} != {manifest["mode"]} or {row["gate_eligible"] for row in rows} != {manifest["gate_eligible"]}:
            raise EvidenceError("row mode differs from the manifest")
        validate_row_artifacts(plan, manifest, rows)
        validate_order(plan, manifest, rows)
        report = summarize(plan, manifest, rows)
        args.output.absolute().parent.mkdir(parents=True, exist_ok=True)
        with args.output.absolute().open("xb") as output:
            output.write(canonical_json(report)); output.flush(); os.fsync(output.fileno())
        print(f"{report['verdict']}: wrote validated summary to {args.output.absolute()}")
        return {"PASS":0,"FAIL":1,"INCONCLUSIVE":2}[report["verdict"]]
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())
