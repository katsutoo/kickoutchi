# Stage 12 Release Benchmark Review

Date: 2026-07-24

## Verdict

Benchmark verdict: BLOCKED.

Release recommendation from this gate: `hold`.

No final benchmark collection was started. The pre-measurement audit found that
the declared plan could have reported `PASS` without measuring several workloads
and resources required by `FEATURE.md`. The plan now declares
`gate_ready=false`, and the controller refuses gate-eligible collection while
retaining bounded smoke use. Running an expensive but incomplete plan would not
create trustworthy gate evidence.

## Reviewed Scope

- `FEATURE.md` release benchmark decisions, workloads, discipline, artifacts,
  and gate requirements.
- `benchmarks/release/plan.json` predeclared identities, workloads, budgets,
  sample counts, bounds, and noise policy.
- `benchmarks/release/controller.py` artifact copying, workload setup, process
  execution, output validation, resource collection, ordering, cleanup, and
  manifest publication.
- `benchmarks/release/summarize.py` evidence validation, distributions,
  uncertainty, budget classification, and size verdicts.
- `benchmarks/release/test_release_benchmark.py`, the qualification workflow,
  existing product limits, watch/diff implementation, and historical benchmark
  fixtures.

Automated correctness gates passed, and native QA run `30052379065` supplied
useful partial evidence, but the complete exploratory QA gate remains blocked.
Candidate identity remains
`7393b56a5d86a5e2afb298cf6d1eb185a77bf02a` from Release run
`30046834702`.

## Blocking Findings

### Required workload coverage is incomplete

The plan currently measures two list workloads, one uncontrolled candidate
snapshot, one Why invocation, and one stable 500 ms watch invocation. It omits:

- an empty machine or isolated namespace baseline;
- controlled typical, large synthetic, and maximum snapshot workloads;
- direct diff-engine throughput for empty, typical, large, and maximum
  snapshots;
- high-churn watch snapshots;
- transient collection failure, recovery, and failure-budget exhaustion;
- distinct cold and warm CLI startup measurements.

`list_high` owns 256 helper sockets. It is neither the legal 262,144-observation
maximum nor a direct diff workload. Snapshot workloads currently receive no
controlled helper sockets.

### The exact artifact exposes no direct diff benchmark seam

The production diff iterator is private Rust code. Existing tests verify its
event bounds and behavior, including the 524,288-event maximum replacement, but
the exact candidate artifact and current controller cannot time that engine
directly. A copied algorithm would not be production-path evidence. Adding a
product benchmark API now would change the candidate and require repeating the
affected security, automated, native CI, QA, and benchmark gates.

The required solution is a benchmark-only, release-optimized helper compiled
from the exact candidate source while leaving production code unchanged, with
its source patch, build command, and binary hash retained. It must consume the
real iterator fully and validate expected event counts for empty, typical,
large, maximum no-change, and maximum replacement inputs.

### Resource budgets and uncertainty are incomplete

- Stable watch has latency budgets but no enforceable CPU, CPU-per-poll, or peak
  memory budgets at the supported 100 ms interval.
- Candidate-only snapshot, Why, and watch workloads have no A/A or equivalent
  calibration lane. Their block ranges cannot classify noisy threshold crossings
  as inconclusive.
- Why and list do not have complete absolute peak-RSS coverage.
- One A/A p99 latency delta is reused as noise for latency, CPU, and memory.
- The classifier checks excessive A/A noise before the candidate absolute p99
  budget, allowing noise to hide an absolute failure.
- Unknown budget keys are accepted even when the summarizer does not enforce
  them.

### Correctness validation is too weak for performance acceptance

- Successful stderr is not required to be empty or retained by digest and byte
  count.
- Snapshot validation checks only schema, version, and a list-shaped `sockets`
  field, not controlled endpoints, exact cardinality, completeness, or omitted
  counts.
- Why validation checks eight results and aggregate status but not the eight
  unique expected endpoint identities, probe completion, verdict shapes, or
  precedence.
- Stable watch validates one baseline endpoint but not all baseline state and
  timing fields.
- The controller-selected Why port is released before all retained samples, so
  an unrelated bind can silently change the workload.

A faster invocation that omits evidence could therefore remain valid, contrary
to the benchmark contract.

### Bounds, cleanup, and environment evidence need remediation

- A legal maximum snapshot can exceed the 32 MiB retained-output cap. Maximum
  serialization needs a bounded-memory counting, digesting, and incremental
  validation sink rather than an arbitrarily larger retained file.
- Timeout cleanup kills only the direct child, not an owned POSIX process group
  or Windows Job Object.
- Output bounds are polled temporary-file sizes rather than enforced by bounded
  readers.
- Windows resource APIs lack explicit 64-bit `ctypes` signatures, so process
  handles and metrics are not sufficiently trustworthy.
- The plan allows eight hours while the workflow kills its benchmark job after
  two hours.
- Environment records omit compiler/target provenance, Windows physical RAM and
  concurrent load, and useful power/thermal state.
- Harness commit identity is recorded but not declared and enforced by the plan.

## Evidence Not Collected

The full Linux and Windows protocol was deliberately not dispatched. There are
no final raw samples, manifests, summaries, percentile tables, or gate-eligible
performance claims. Historical list, snapshot, Why, watch, RSS, and size files
remain implementation or feasibility evidence only and are not promoted to this
gate.

The current plan's 10,000 retained process samples for fast declared workloads
and 2,000 independent stable-watch process samples are adequate sample shapes
for those workloads. Sample count does not compensate for omitted workloads,
weak correctness validation, missing resource budgets, or an unavailable
production-path diff measurement.

## Required Remediation

Before measurement:

1. Create and review a new immutable plan; do not rewrite a plan after samples
   exist.
2. Add controlled empty, typical, large, and maximum snapshot/list fixtures.
3. Add the exact-source release-optimized diff helper and validate complete
   iterator exhaustion and event counts.
4. Add synchronized high-churn and transient-failure workloads with exact event
   validation and test-owned cleanup.
5. Add cold/warm startup separation and absolute CPU/RSS/watch-poll budgets.
6. Add candidate-only calibration and metric-specific uncertainty; absolute
   safety budgets must fail regardless of noise.
7. Strengthen every output validator and retain bounded stdout and stderr
   identities.
8. Enforce process-tree cleanup, hard output bounds, strict budget schemas,
   harness identity, complete environment metadata, and aligned timeouts.
9. Expand harness tests for malformed outputs, missing metrics, cleanup,
   unknown budgets, classifier precedence, Windows APIs, and manifest counts.
10. Pass a bounded Linux and Windows smoke preflight before dispatching the full
    native protocol.

## Formal Gate Status

- [ ] Correctness and the complete exploratory QA gate were verified before measurement.
- [ ] Baseline and candidate were measured under equivalent conditions.
- [ ] No practical regression budget was exceeded.
- [ ] Results are reproducible and include uncertainty and caveats.
- [ ] Linux and Windows results use the declared native sampling protocol.
- [ ] Binary and dependency growth are justified.

The `FEATURE.md` benchmark gate remains open. The next release step is not
ready.
