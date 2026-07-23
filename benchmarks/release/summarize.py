#!/usr/bin/env python3
import argparse
import json
import math
import os
import sys
from pathlib import Path
from typing import Any

if __package__:
    from .common import (
        MANIFEST_BYTES_MAX, MAX_TOTAL_ROWS, PLAN_BYTES_MAX, RAW_BYTES_MAX, EvidenceError,
        balanced_orders, canonical_json, nearest_rank, read_json, read_regular,
        require_absent, sha256_bytes, validate_plan,
    )
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from benchmarks.release.common import (  # type: ignore[no-redef]
        MANIFEST_BYTES_MAX, MAX_TOTAL_ROWS, PLAN_BYTES_MAX, RAW_BYTES_MAX, EvidenceError,
        balanced_orders, canonical_json, nearest_rank, read_json, read_regular,
        require_absent, sha256_bytes, validate_plan,
    )


def delta_percent(baseline: int | float, candidate: int | float) -> float:
    if baseline <= 0:
        return 0.0 if candidate == baseline else math.inf
    return (candidate - baseline) * 100.0 / baseline


def distribution(rows: list[dict[str, Any]]) -> dict[str, Any]:
    latency = [row["latency_ns"] for row in rows if row["outcome"] == "valid"]
    if not latency:
        return {"samples": 0, "failures": len(rows)}
    block_p99 = []
    for block in sorted({row["block"] for row in rows}):
        values = [row["latency_ns"] for row in rows if row["block"] == block and row["outcome"] == "valid"]
        if values:
            block_p99.append(nearest_rank(values, 99))
    cpu = [row["user_cpu_ns"] + row["system_cpu_ns"] for row in rows
           if row["outcome"] == "valid" and row["user_cpu_ns"] is not None and row["system_cpu_ns"] is not None]
    user_cpu = [row["user_cpu_ns"] for row in rows if row["outcome"] == "valid" and row["user_cpu_ns"] is not None]
    system_cpu = [row["system_cpu_ns"] for row in rows if row["outcome"] == "valid" and row["system_cpu_ns"] is not None]
    memory = [row["peak_memory_bytes"] for row in rows if row["outcome"] == "valid" and row["peak_memory_bytes"] is not None]
    total_latency_ns = sum(latency)
    total_rows = sum(row["row_count"] for row in rows if row["outcome"] == "valid")
    total_events = sum(row["event_count"] for row in rows if row["outcome"] == "valid")
    failure_statuses: dict[str, int] = {}
    failure_errors: dict[str, int] = {}
    for row in rows:
        if row["outcome"] != "valid":
            status = str(row["status"])
            error = row.get("error") or "unspecified"
            failure_statuses[status] = failure_statuses.get(status, 0) + 1
            failure_errors[error] = failure_errors.get(error, 0) + 1
    return {
        "samples": len(latency), "failures": len(rows) - len(latency),
        "failure_statuses": failure_statuses, "failure_errors": failure_errors,
        "p50_latency_ns": nearest_rank(latency, 50), "p95_latency_ns": nearest_rank(latency, 95),
        "p99_latency_ns": nearest_rank(latency, 99), "max_latency_ns": max(latency),
        "block_p99_min_ns": min(block_p99), "block_p99_max_ns": max(block_p99),
        "p50_cpu_ns": nearest_rank(cpu, 50) if cpu else None,
        "p50_user_cpu_ns": nearest_rank(user_cpu, 50) if user_cpu else None,
        "p50_system_cpu_ns": nearest_rank(system_cpu, 50) if system_cpu else None,
        "peak_memory_bytes": max(memory) if memory else None,
        "throughput_invocations_per_second": len(latency) * 1_000_000_000 / total_latency_ns,
        "throughput_rows_per_second": total_rows * 1_000_000_000 / total_latency_ns,
        "throughput_events_per_second": total_events * 1_000_000_000 / total_latency_ns,
        "measurement_duration_ns": total_latency_ns,
        "row_count_min": min(row["row_count"] for row in rows if row["outcome"] == "valid"),
        "row_count_max": max(row["row_count"] for row in rows if row["outcome"] == "valid"),
        "event_count_min": min(row["event_count"] for row in rows if row["outcome"] == "valid"),
        "event_count_max": max(row["event_count"] for row in rows if row["outcome"] == "valid"),
    }


def classify_comparison(
    budgets: dict[str, float], baseline: dict[str, Any], candidate: dict[str, Any],
    aa_p99_delta: float, noise_limit: float, noise_multiplier: float,
) -> tuple[str, list[str], dict[str, float]]:
    reasons: list[str] = []
    deltas: dict[str, float] = {}
    if baseline.get("failures", 0) or candidate.get("failures", 0):
        return "FAIL", ["one or more measured invocations failed output validation"], deltas
    if aa_p99_delta > noise_limit:
        return "INCONCLUSIVE", [f"A/A p99 delta {aa_p99_delta:.3f}% exceeds {noise_limit:.3f}%"], deltas
    absolute_p99 = budgets.get("p99_latency_ns_max")
    if absolute_p99 is not None and candidate.get("p99_latency_ns", math.inf) > absolute_p99:
        return "FAIL", [f"p99_latency_ns exceeds absolute budget {absolute_p99:.0f}"], deltas
    metric_map = {
        "p50_delta_percent_max": "p50_latency_ns", "p95_delta_percent_max": "p95_latency_ns",
        "p99_delta_percent_max": "p99_latency_ns", "max_delta_percent_max": "max_latency_ns",
        "cpu_delta_percent_max": "p50_cpu_ns", "rss_delta_percent_max": "peak_memory_bytes",
    }
    verdict = "PASS"
    for budget_name, metric in metric_map.items():
        if budget_name not in budgets:
            continue
        if baseline.get(metric) is None or candidate.get(metric) is None:
            verdict = "INCONCLUSIVE"
            reasons.append(f"{metric} is unavailable")
            continue
        delta = delta_percent(baseline[metric], candidate[metric])
        deltas[metric] = delta
        if delta > budgets[budget_name]:
            if delta > aa_p99_delta * noise_multiplier:
                verdict = "FAIL"
                reasons.append(f"{metric} regression {delta:.3f}% exceeds budget {budgets[budget_name]:.3f}% and noise rule")
            elif verdict != "FAIL":
                verdict = "INCONCLUSIVE"
                reasons.append(f"{metric} exceeds its budget but not the A/A noise multiplier")
    return verdict, reasons, deltas


def _bounded_nonnegative(value: Any, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise EvidenceError(f"invalid observation {name}")
    return value


def parse_rows(raw: bytes, plan_hash: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line:
            raise EvidenceError(f"empty JSONL record at line {line_number}")
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EvidenceError(f"malformed JSONL at line {line_number}: {error}") from error
        if not isinstance(row, dict) or row.get("schema") != "kickoutchi.release_observation" or row.get("version") != 1:
            raise EvidenceError(f"invalid observation schema at line {line_number}")
        if row.get("plan_sha256") != plan_hash or row.get("mode") not in {"final", "smoke"}:
            raise EvidenceError(f"observation identity mismatch at line {line_number}")
        for key, maximum in (("latency_ns", 120_000_000_000), ("status", 255), ("stdout_bytes", 64 * 1024 * 1024),
                             ("row_count", 262_144), ("event_count", 524_288), ("artifact_bytes", 256 * 1024 * 1024)):
            _bounded_nonnegative(row.get(key), key, maximum)
        for key, maximum in (("block", 100), ("pair", 10_000), ("order", 2), ("sample", 500_000)):
            if _bounded_nonnegative(row.get(key), key, maximum) == 0:
                raise EvidenceError(f"observation {key} must be positive")
        for key in ("user_cpu_ns", "system_cpu_ns", "peak_memory_bytes"):
            if row.get(key) is not None:
                _bounded_nonnegative(row[key], key, 120_000_000_000 if key != "peak_memory_bytes" else 1 << 50)
        if row.get("outcome") not in {"valid", "error"} or row.get("artifact_role") not in {"baseline", "candidate"}:
            raise EvidenceError(f"invalid observation outcome or role at line {line_number}")
        for key in ("artifact_sha256", "output_sha256"):
            value = row.get(key)
            if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise EvidenceError(f"invalid observation {key} at line {line_number}")
        rows.append(row)
        if len(rows) > MAX_TOTAL_ROWS:
            raise EvidenceError(f"observation count exceeds {MAX_TOTAL_ROWS}")
    return rows


def validate_order(plan: dict[str, Any], manifest: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    mode = manifest["mode"]
    cursor = 0
    sample_counts: dict[tuple[str, str, str], int] = {}
    for declared in plan["workloads"]:
        workload = dict(declared)
        if mode == "smoke":
            workload["blocks"], workload["warmups"] = 1, 1
            workload["samples_per_block"] = 4 if workload["comparison"] == "baseline_candidate" else 2
        for block in range(1, workload["blocks"] + 1):
            orders = balanced_orders(plan["ordering_seed"], workload["name"], block, workload["samples_per_block"])
            for pair, order_names in enumerate(orders, 1):
                expected: list[tuple[str, str, str, int]] = []
                if workload["comparison"] == "baseline_candidate":
                    for comparison in ("aa", "ab"):
                        for position, side in enumerate(order_names, 1):
                            role = "baseline" if comparison == "aa" or side == "left" else "candidate"
                            expected.append((comparison, role, side, position))
                else:
                    expected.append(("candidate_only", "candidate", "candidate", 1))
                for comparison, role, side, position in expected:
                    if cursor >= len(rows):
                        raise EvidenceError("raw observations end before the declared plan")
                    row = rows[cursor]
                    actual = (row.get("workload"), row.get("block"), row.get("pair"), row.get("comparison"),
                              row.get("artifact_role"), row.get("lane_side"), row.get("order"))
                    wanted = (workload["name"], block, pair, comparison, role, side, position)
                    if actual != wanted:
                        raise EvidenceError(f"observation order mismatch at row {cursor + 1}: expected {wanted}, got {actual}")
                    sample_key = (workload["name"], comparison, role)
                    sample_counts[sample_key] = sample_counts.get(sample_key, 0) + 1
                    if row["sample"] != sample_counts[sample_key]:
                        raise EvidenceError(f"observation sample sequence mismatch at row {cursor + 1}")
                    if row.get("command") != manifest.get("commands", {}).get(workload["name"]):
                        raise EvidenceError(f"observation command mismatch at row {cursor + 1}")
                    cursor += 1
    if cursor != len(rows):
        raise EvidenceError("raw observations continue beyond the declared plan")


def validate_manifest(plan: dict[str, Any], manifest: dict[str, Any]) -> None:
    mode = manifest.get("mode")
    if mode not in {"final", "smoke"} or manifest.get("gate_eligible") is not (mode == "final"):
        raise EvidenceError("manifest mode and gate eligibility are inconsistent")
    if manifest.get("source_commit") != plan["artifacts"]["candidate"]["source_commit"]:
        raise EvidenceError("manifest candidate source identity does not match the plan")
    if manifest.get("versions") != {"baseline": "kickoutchi 1.2.0", "candidate": "kickoutchi 1.3.0"}:
        raise EvidenceError("manifest artifact versions are invalid")
    commands = manifest.get("commands")
    if not isinstance(commands, dict):
        raise EvidenceError("manifest commands are missing")
    for workload in plan["workloads"]:
        actual = commands.get(workload["name"])
        expected = workload["semantics"]["command"]
        if any(isinstance(value, str) and value.startswith("{controller_") for value in expected):
            if not isinstance(actual, list) or len(actual) != len(expected):
                raise EvidenceError(f"manifest command is invalid for {workload['name']}")
            for actual_value, expected_value in zip(actual, expected):
                if isinstance(expected_value, str) and expected_value.startswith("{controller_"):
                    if not isinstance(actual_value, str) or not actual_value.isascii() or not actual_value.isdecimal() or not 1 <= int(actual_value) <= 65535:
                        raise EvidenceError(f"manifest controller-selected port is invalid for {workload['name']}")
                elif actual_value != expected_value:
                    raise EvidenceError(f"manifest command differs from plan for {workload['name']}")
        elif actual != expected:
            raise EvidenceError(f"manifest command differs from plan for {workload['name']}")
    platform_key = manifest.get("platform_key")
    if not isinstance(platform_key, str):
        raise EvidenceError("manifest platform key is invalid")
    for role in ("baseline", "candidate"):
        expected_hash = plan["artifacts"][role]["sha256_by_platform"].get(platform_key)
        if not expected_hash:
            raise EvidenceError(f"plan has no {role} artifact hash for the measured platform")
        if manifest.get("artifacts", {}).get(role, {}).get("sha256") != expected_hash:
            raise EvidenceError(f"manifest {role} hash differs from the plan")


def summarize(plan: dict[str, Any], manifest: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    noise = plan["noise_rule"]
    workload_reports = []
    overall = "PASS"
    for workload in plan["workloads"]:
        selected = [row for row in rows if row["workload"] == workload["name"]]
        if workload["comparison"] == "baseline_candidate":
            aa_left = distribution([row for row in selected if row["comparison"] == "aa" and row["lane_side"] == "left"])
            aa_right = distribution([row for row in selected if row["comparison"] == "aa" and row["lane_side"] == "right"])
            baseline = distribution([row for row in selected if row["comparison"] == "ab" and row["artifact_role"] == "baseline"])
            candidate = distribution([row for row in selected if row["comparison"] == "ab" and row["artifact_role"] == "candidate"])
            if aa_left.get("failures") or aa_right.get("failures") or not aa_left.get("samples") or not aa_right.get("samples"):
                aa_delta = math.inf
                verdict, reasons, deltas = "FAIL", ["one or more A/A invocations failed output validation"], {}
            else:
                aa_delta = abs(delta_percent(aa_left["p99_latency_ns"], aa_right["p99_latency_ns"]))
                verdict, reasons, deltas = classify_comparison(workload["budgets"], baseline, candidate, aa_delta,
                                                                noise["aa_p99_delta_limit_percent"], noise["aa_multiplier"])
            report = {"name": workload["name"], "comparison_supported": True, "verdict": verdict, "reasons": reasons,
                      "aa": {"left": aa_left, "right": aa_right, "p99_absolute_delta_percent": aa_delta},
                      "baseline": baseline, "candidate": candidate, "deltas_percent": deltas, "budgets": workload["budgets"]}
        else:
            candidate = distribution(selected)
            reasons = []
            verdict = "FAIL" if candidate.get("failures", 0) else "PASS"
            if candidate.get("failures", 0):
                reasons.append("one or more candidate-only invocations failed output validation")
            for budget_name, metric in (("p99_latency_ns_max", "p99_latency_ns"), ("max_latency_ns_max", "max_latency_ns")):
                if candidate.get(metric, math.inf) > workload["budgets"].get(budget_name, math.inf):
                    verdict = "FAIL"; reasons.append(f"{metric} exceeds absolute candidate-only budget")
            report = {"name": workload["name"], "comparison_supported": False, "verdict": verdict, "reasons": reasons,
                      "candidate": candidate, "budgets": workload["budgets"],
                      "note": "The published v1.2.0 baseline does not support this command; no baseline comparison is claimed."}
        workload_reports.append(report)
        if report["verdict"] == "FAIL": overall = "FAIL"
        elif report["verdict"] == "INCONCLUSIVE" and overall != "FAIL": overall = "INCONCLUSIVE"
    artifacts = manifest["artifacts"]
    size_delta = delta_percent(artifacts["baseline"]["bytes"], artifacts["candidate"]["bytes"])
    size_budget = plan["artifact_budgets"]
    size_verdict = "PASS"
    if artifacts["candidate"]["bytes"] > size_budget["candidate_size_bytes_max"] or size_delta > size_budget["candidate_size_delta_percent_max"]:
        size_verdict = "FAIL"; overall = "FAIL"
    if not manifest["gate_eligible"] and overall == "PASS":
        overall = "INCONCLUSIVE"
    return {"schema": "kickoutchi.release_benchmark_summary", "version": 1, "verdict": overall,
            "gate_eligible": manifest["gate_eligible"], "mode": manifest["mode"],
            "plan_sha256": manifest["plan_sha256"], "raw_sha256": manifest["raw_sha256"],
            "artifacts": artifacts, "artifact_size_delta_percent": size_delta, "artifact_size_verdict": size_verdict,
            "workloads": workload_reports,
            "caveats": ["Smoke mode is local validation only and cannot pass the release gate."] if not manifest["gate_eligible"] else []}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and summarize native release JSONL without averaging percentiles.")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        plan, plan_bytes = read_json(args.plan, PLAN_BYTES_MAX)
        manifest, _ = read_json(args.manifest, MANIFEST_BYTES_MAX)
        if not isinstance(manifest, dict):
            raise EvidenceError("manifest must be a JSON object")
        validate_plan(plan, require_gate_ready=manifest.get("mode") != "smoke")
        raw = read_regular(args.raw, RAW_BYTES_MAX)
        require_absent(args.output.absolute())
        plan_hash = sha256_bytes(plan_bytes)
        if manifest.get("schema") != "kickoutchi.release_benchmark_manifest" or manifest.get("version") != 1 or not manifest.get("complete"):
            raise EvidenceError("manifest is not a complete kickoutchi.release_benchmark_manifest/1")
        validate_manifest(plan, manifest)
        if manifest.get("plan_sha256") != plan_hash or manifest.get("raw_sha256") != sha256_bytes(raw):
            raise EvidenceError("plan or raw evidence hash does not match the manifest")
        rows = parse_rows(raw, plan_hash)
        if manifest.get("row_count") != len(rows):
            raise EvidenceError("manifest row count does not match raw evidence")
        if manifest.get("failure_count") != sum(row["outcome"] != "valid" for row in rows):
            raise EvidenceError("manifest failure count does not match raw evidence")
        mode_values = {row["mode"] for row in rows}
        eligible_values = {row.get("gate_eligible") for row in rows}
        if mode_values != {manifest.get("mode")} or eligible_values != {manifest.get("gate_eligible")}:
            raise EvidenceError("row mode or eligibility is inconsistent with manifest")
        for role in ("baseline", "candidate"):
            identity = manifest.get("artifacts", {}).get(role, {})
            role_rows = [row for row in rows if row["artifact_role"] == role]
            if not role_rows or {row["artifact_sha256"] for row in role_rows} != {identity.get("sha256")} or {row["artifact_bytes"] for row in role_rows} != {identity.get("bytes")}:
                raise EvidenceError(f"{role} artifact identity is inconsistent")
        validate_order(plan, manifest, rows)
        report = summarize(plan, manifest, rows)
        output = args.output.absolute(); output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as file:
            file.write(canonical_json(report)); file.flush(); os.fsync(file.fileno())
        print(f"{report['verdict']}: wrote validated summary to {output}")
        return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 2}[report["verdict"]]
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())
