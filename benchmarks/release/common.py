#!/usr/bin/env python3
import hashlib
import json
import math
import os
import stat
from pathlib import Path
from typing import Any

PLAN_BYTES_MAX = 1024 * 1024
RAW_BYTES_MAX = 128 * 1024 * 1024
MANIFEST_BYTES_MAX = 16 * 1024 * 1024
ARTIFACT_BYTES_MAX = 256 * 1024 * 1024
MAX_BLOCKS = 100
MAX_SAMPLES_PER_BLOCK = 10_000
MAX_WARMUPS = 100
MAX_TOTAL_ROWS = 500_000
MAX_HELPER_SOCKETS = 1024


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
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - retained))
            if not chunk:
                break
            retained += len(chunk)
            if retained > maximum:
                raise EvidenceError(f"file exceeds {maximum} bytes: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
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


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EvidenceError(f"{name} must be an integer in {minimum}..={maximum}")
    return value


def validate_plan(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict) or plan.get("schema") != "kickoutchi.release_benchmark_plan" or plan.get("version") != 1:
        raise EvidenceError("plan must be kickoutchi.release_benchmark_plan/1")
    if plan.get("immutable") is not True or plan.get("gate_mode") != "final":
        raise EvidenceError("plan must declare immutable=true and gate_mode=final")
    for role, expected in (("baseline", "1.2.0"), ("candidate", "1.3.0")):
        identity = plan.get("artifacts", {}).get(role)
        if not isinstance(identity, dict) or identity.get("version") != expected:
            raise EvidenceError(f"{role} version must be {expected}")
        hashes = identity.get("sha256_by_platform", {})
        if not isinstance(hashes, dict) or any(
            not isinstance(key, str) or not isinstance(value, str) or len(value) != 64
            for key, value in hashes.items()
        ):
            raise EvidenceError(f"{role} sha256_by_platform is invalid")
    baseline = plan["artifacts"]["baseline"]
    if baseline.get("published") is not True or baseline.get("tag") != "v1.2.0" or not isinstance(baseline.get("release_url"), str):
        raise EvidenceError("baseline must identify the published v1.2.0 release")
    candidate = plan["artifacts"]["candidate"]
    if not isinstance(candidate.get("source_commit"), str) or len(candidate["source_commit"]) != 40:
        raise EvidenceError("candidate source_commit must be a full Git object ID")
    bounds = plan.get("bounds")
    if not isinstance(bounds, dict):
        raise EvidenceError("plan bounds are missing")
    _integer(bounds.get("artifact_bytes_max"), "artifact_bytes_max", 1, ARTIFACT_BYTES_MAX)
    _integer(bounds.get("output_bytes_max"), "output_bytes_max", 1024, 64 * 1024 * 1024)
    _integer(bounds.get("child_timeout_seconds"), "child_timeout_seconds", 1, 120)
    _integer(bounds.get("run_timeout_seconds"), "run_timeout_seconds", 1, 24 * 60 * 60)
    _integer(bounds.get("max_failures"), "max_failures", 1, 1000)
    cleanup = plan.get("stop_cleanup_rules")
    if not isinstance(cleanup, dict) or cleanup.get("stop_after_measured_failures") != bounds["max_failures"]:
        raise EvidenceError("stop_cleanup_rules must match the measured failure bound")
    noise = plan.get("noise_rule")
    if not isinstance(noise, dict):
        raise EvidenceError("noise_rule is missing")
    for name in ("aa_p99_delta_limit_percent", "aa_multiplier"):
        value = noise.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0 or not math.isfinite(value):
            raise EvidenceError(f"noise_rule.{name} must be a positive finite number")
    workloads = plan.get("workloads")
    if not isinstance(workloads, list) or not workloads:
        raise EvidenceError("plan workloads must be a nonempty array")
    names: set[str] = set()
    total_rows = 0
    for workload in workloads:
        if not isinstance(workload, dict) or not isinstance(workload.get("name"), str) or workload["name"] in names:
            raise EvidenceError("workload names must be unique strings")
        names.add(workload["name"])
        kind = workload.get("kind")
        if kind not in {"list", "snapshot", "why", "watch"}:
            raise EvidenceError(f"invalid workload kind: {kind}")
        comparison = workload.get("comparison")
        if comparison not in {"baseline_candidate", "candidate_only"}:
            raise EvidenceError(f"invalid comparison for {workload['name']}")
        if (kind == "list") != (comparison == "baseline_candidate"):
            raise EvidenceError("only list workloads may compare the v1.2.0 baseline")
        blocks = _integer(workload.get("blocks"), "blocks", 1, MAX_BLOCKS)
        samples = _integer(workload.get("samples_per_block"), "samples_per_block", 2, MAX_SAMPLES_PER_BLOCK)
        _integer(workload.get("warmups"), "warmups", 0, MAX_WARMUPS)
        if comparison == "baseline_candidate" and samples % 2:
            raise EvidenceError("comparison samples_per_block must be even for exact balancing")
        if kind in {"list", "snapshot", "why"} and blocks * samples < 10_000:
            raise EvidenceError("fast process workloads must retain at least 10000 samples")
        multiplier = 4 if comparison == "baseline_candidate" else 1
        total_rows += blocks * samples * multiplier
        semantics = workload.get("semantics")
        budgets = workload.get("budgets")
        if not isinstance(semantics, dict) or not isinstance(budgets, dict) or not budgets:
            raise EvidenceError(f"{workload['name']} must declare semantics and budgets")
        for budget_name, budget in budgets.items():
            if isinstance(budget, bool) or not isinstance(budget, (int, float)) or budget < 0 or not math.isfinite(budget):
                raise EvidenceError(f"invalid {workload['name']} budget {budget_name}")
        if kind == "list":
            per_variant = _integer(semantics.get("sockets_per_variant"), "sockets_per_variant", 1, MAX_HELPER_SOCKETS // 4)
            if per_variant * 4 > MAX_HELPER_SOCKETS:
                raise EvidenceError("helper socket count exceeds bound")
        if kind == "watch" and blocks * samples != 2000:
            raise EvidenceError("final watch workload must declare exactly 2000 process samples")
    if total_rows > MAX_TOTAL_ROWS:
        raise EvidenceError(f"planned rows exceed {MAX_TOTAL_ROWS}")
    return plan


def balanced_orders(seed: int, workload: str, block: int, pairs: int) -> list[tuple[str, str]]:
    if pairs < 2 or pairs % 2:
        raise EvidenceError("balanced pair count must be positive and even")
    material = f"{seed}:{workload}:{block}".encode()
    ranked = sorted(range(pairs), key=lambda item: hashlib.sha256(material + b":" + str(item).encode()).digest())
    reversed_pairs = set(ranked[: pairs // 2])
    return [("right", "left") if item in reversed_pairs else ("left", "right") for item in range(pairs)]


def nearest_rank(values: list[int], percent: int) -> int:
    if not values or percent < 1 or percent > 100:
        raise EvidenceError("percentile requires values and a percent in 1..=100")
    ordered = sorted(values)
    return ordered[(len(ordered) * percent + 99) // 100 - 1]
