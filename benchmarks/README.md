# Benchmark Protocol

Benchmark exact release-profile artifacts, never `cargo run` or debug builds.
The earlier native-collection feasibility check used `list --json` as a
conservative end-to-end collection workload before the watch command existed.

Build and collect raw samples with:

```sh
cargo build --locked --profile dist --all-features --bin kickoutchi --bin kick
benchmarks/collect-list-samples.py target/dist/kick 200 8 \
  /tmp/kickoutchi-list-latency.tsv
benchmarks/summarize-list-samples.py /tmp/kickoutchi-list-latency.tsv
benchmarks/measure-linux-peak-rss.py target/dist/kick 20
```

Collect the stable-watch gate workload separately from the build so Linux child
resource high-water marks cannot inherit compiler RSS:

```sh
python benchmarks/collect-watch-samples.py target/dist/kick 100 4 watch \
  benchmarks/watch-stable-2026-07-21.tsv
python benchmarks/summarize-list-samples.py \
  benchmarks/watch-stable-2026-07-21.tsv
python benchmarks/measure-linux-peak-rss.py target/dist/kick 20 watch \
  benchmarks/watch-stable-rss-2026-07-21.tsv
```

The workload runs a filtered, stable watch at the supported 100 ms minimum
interval for 500 ms. It measures release-binary lifecycle latency, CPU, failures,
and artifact identity. Peak RSS is collected separately so warmups and latency
sampling cannot change its scope. This does not replace the final interleaved
release benchmark for high churn, maximum snapshots, failures, or native runs on
all supported platforms.

Collect the complete Why matrix with retained source and artifact identity:

```sh
python benchmarks/collect-watch-samples.py target/dist/kick 30 3 why \
  benchmarks/why-complete-2026-07-22.tsv
python benchmarks/summarize-list-samples.py \
  benchmarks/why-complete-2026-07-22.tsv
python benchmarks/measure-linux-peak-rss.py target/dist/kick 10 why \
  benchmarks/why-complete-rss-2026-07-22.tsv
```

The Why workload evaluates TCP and UDP over the four canonical loopback and
wildcard addresses. Exit `0` and aggregate unavailable exit `3` are both valid;
the harness parses one result before sampling and requires exactly eight
endpoints with an aggregate field matching the process status.

Collect the complete within-scope snapshot workload with:

```sh
python benchmarks/collect-watch-samples.py target/dist/kick 30 3 snapshot \
  benchmarks/snapshot-complete-2026-07-22.tsv
python benchmarks/summarize-list-samples.py \
  benchmarks/snapshot-complete-2026-07-22.tsv
python benchmarks/measure-linux-peak-rss.py target/dist/kick 10 snapshot \
  benchmarks/snapshot-complete-rss-2026-07-22.tsv
```

The harness parses one release-binary result before sampling and requires the
`kickoutchi.snapshot/1` schema/version pair. The workload includes native
collection, canonical index construction, and streamed serialization to a
discarded stdout consumer.

The latency script records one bounded child-process invocation per row with its
nanosecond duration and exit status. It writes environment, source, patch, and
artifact identifiers as comment lines. It also writes an applyable
`*.source.patch` beside the TSV that captures every tracked and untracked product
or harness change relative to the recorded commit. Keep both files in an
immutable CI artifact or attach them to the implementation review. Do not cite
results when either file is unavailable or its checksum does not match.
The retained patch deliberately has zero context so it does not embed whitespace
on blank context lines; verify or apply it with `git apply --unidiff-zero` from
the recorded source commit.

The collect-watch grammar is `BINARY [SAMPLES [WARMUPS [WORKLOAD [OUTPUT]]]]`,
where `WORKLOAD` is exactly `watch`, `why`, or `snapshot`. Supplying an output
therefore also requires an explicit workload. Collect-list follows the same tracked and
untracked companion-patch provenance policy. All latency and RSS producers
publish completed files with exclusive creation and refuse existing TSV or
companion-patch paths; choose a new evidence name rather than replacing one.

On Linux, the peak-RSS helper runs independent invocations and obtains their
high-water mark from `wait4` through Python's `resource.getrusage`. Report the
maximum value, failure count, and sample count. Collect latency and RSS
separately.

For native-collection acceptance, record the workload's process, descriptor, socket, and row
counts; machine CPU/RAM; OS/kernel; Rust version; power state; concurrent load;
artifact SHA-256; warmups; sample count; p50/p95/p99/max; failures; and peak RSS.
Compare the measured tail against the predeclared 100 ms watch floor. This is a
feasibility decision, not a cross-machine performance promise.

The final release benchmark must additionally interleave baseline and candidate
artifacts under the same live or synthetic workload and preserve its ordering
seed and all raw samples.

Named-endpoint gate evidence is retained in the five
`named-endpoints-*-2026-07-21.tsv` files. The maximum legal selector workload is
`named-endpoints-max-selectors.toml`; regenerate it to a new path with:

```sh
python benchmarks/generate-max-label-config.py /tmp/max-labels.toml
```

The generator uses exclusive creation so it cannot overwrite existing evidence.

The historical Windows native-validation bundle consists of
`windows-native-validation.ps1`, `windows-native-qa-postfix-2026-07-22.json`,
and `windows-watch-postfix-2026-07-22.tsv`. The two `postfix` outputs record the
post-remediation native QA and 100-sample stable-watch run from commit
`4151d8c558e584508c2c0547527fde3ef29cc5ba`; they are supporting historical
evidence, not the final release gate or interleaved release benchmark. Run the
harness on Windows with an unused output path, for example:

```powershell
benchmarks\windows-native-validation.ps1 -Mode qa `
  -Output benchmarks\windows-native-qa-NEW.json
benchmarks\windows-native-validation.ps1 -Mode benchmark `
  -Output benchmarks\windows-watch-NEW.tsv
```

## Native Release Controller

The standard-library-only controller and summarizer in `benchmarks/release/`
implement protocol version 2. The plan uses exact-key validation: unknown plan,
workload, sampling, fixture, expected-output, calibration, or budget fields are
errors. It declares the complete matrix, final sample shapes, metric-specific
calibration limits, absolute and relative budgets, output bounds, process-tree
cleanup, and required environment evidence. Every raw row carries the immutable
plan hash. Never edit a plan after collection.

The checked-in plan deliberately remains `gate_ready=false`. Isolated empty
namespace collection, large/maximum snapshot serialization, and synchronized
high-churn and collection-failure drivers are declared but marked unimplemented.
Protocol identity fields also remain unset until the exact reviewed source, lock
file, target, compiler, and harness tree are frozen. Gate collection rejects any
unavailable driver or identity; smoke mode skips those workloads and records
them as inconclusive.

The private diff helper is not part of either shipped binary. It includes the
candidate's real private `model`, `observation`, and `watch` modules by source
path, consumes the real diff iterator to exhaustion, and validates exact event
counts for empty, typical, large, maximum no-change, and maximum replacement
fixtures. Build it with the retained lock file and release settings:

```sh
cargo build --locked --release \
  --manifest-path benchmarks/release/diff_helper/Cargo.toml
```

Retain the helper source, `Cargo.lock`, build command, source commit, compiler
target, and helper binary SHA-256 beside the raw evidence. Source inclusion means
the helper cannot silently benchmark a copied algorithm and does not change the
shipping artifact.

Use extracted native release binaries, not Cargo wrappers. Both executable
hashes must match the platform entry in the plan. A collection command is:

```sh
python3 benchmarks/release/controller.py \
  --plan benchmarks/release/plan.json \
  --baseline /absolute/path/to/extracted/v1.2.0/kick \
  --candidate /absolute/path/to/extracted/v1.3.0/kick \
  --diff-helper /absolute/path/to/kickoutchi-release-diff-helper \
  --output /absolute/new/path/release-raw.jsonl \
  --manifest /absolute/new/path/release-manifest.json
python3 benchmarks/release/summarize.py \
  --plan benchmarks/release/plan.json \
  --raw /absolute/new/path/release-raw.jsonl \
  --manifest /absolute/new/path/release-manifest.json \
  --output /absolute/new/path/release-summary.json
```

Add `--smoke` for four retained observations per available workload. Smoke
evidence is always non-gate and its summary is always `INCONCLUSIVE` unless an
absolute failure makes it `FAIL`.

The controller privately copies and hashes every executable, validates versions
and workload output before timing, reserves the Why TCP port for the complete
workload, and publishes only complete absent paths. Reader threads retain a
bounded prefix while hashing and counting the complete bounded stdout/stderr
streams. Timeout or overflow terminates the POSIX process group or Windows Job
Object. Windows process-time and memory APIs use explicit `ctypes` argument and
result signatures. Every valid invocation requires empty stderr and the exact
structured-output contract.

Cold startup receives a fresh home/config directory for each retained process.
Warm startup reuses one directory and performs block warmups. List typical/high
are interleaved baseline/candidate comparisons with baseline A/A calibration.
Snapshots, the full eight-endpoint Why matrix, watches, and diffs are
candidate-only and use paired same-artifact calibration. Candidate-only declared
sample counts are split evenly across calibration sides, not doubled.

The classifier checks correctness and absolute maxima/minima before noise.
Relative regressions use only the matching metric's calibration delta; one noisy
latency metric cannot excuse CPU or memory. Missing required metrics and noisy
threshold crossings are `INCONCLUSIVE`. The summarizer recomputes nearest-rank
p50/p95/p99/max and block-p99 ranges from raw observations and validates exact
ordering, counts, commands, hashes, and manifest environment fields.

The final declared protocol retains ten 1,000-observation blocks with 10 to 20
warmups for fast process workloads, 2,000 process observations in ten blocks for
each 500 ms watch workload, and ten bounded blocks for expensive large/maximum
operations. On the historical 20-35 ms one-shot range, the complete matrix is
expected to take roughly 3.5 to 5.5 hours per native machine, dominated by watch
duration and 270,000-plus one-shot process invocations. The current two-hour
single-run bound therefore requires reviewed workload sharding and aggregate
manifest support before the plan can become gate-ready.

Run the unit tests with:

```sh
python3 -m unittest benchmarks.release.test_release_benchmark
cargo check --locked --release \
  --manifest-path benchmarks/release/diff_helper/Cargo.toml
```
