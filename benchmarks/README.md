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

The standard-library-only controller in `benchmarks/release/` is the final
native release comparison harness. Its immutable JSON plan identifies the
published v1.2.0 baseline and the v1.3.0 candidate source, fixes the ordering
seed, workload semantics, practical budgets, A/A noise policy, warmups, blocks,
sample counts, timeouts, output limits, helper-socket limits, and cleanup rules.
Do not edit a plan after collection; a plan hash is carried by every raw row and
the manifest. Create and review a new plan instead.

The checked-in plan currently declares `gate_ready=false` because its workload
matrix is incomplete. It may be used only with `--smoke`; the controller refuses
gate-eligible collection until a replacement plan covers every required
workload and passes review.

Use extracted native release binaries, not Cargo wrappers. The candidate must
come from the source commit declared by the plan. The reviewed native executable
checksums in `sha256_by_platform` are mandatory; the controller refuses a
platform without both artifact identities and refuses a private snapshot that
does not match.

Exact final collection and summary commands are:

```sh
python3 benchmarks/release/controller.py \
  --plan benchmarks/release/plan.json \
  --baseline /absolute/path/to/extracted/v1.2.0/kick \
  --candidate /absolute/path/to/extracted/v1.3.0/kick \
  --output /absolute/new/path/release-raw.jsonl \
  --manifest /absolute/new/path/release-manifest.json
python3 benchmarks/release/summarize.py \
  --plan benchmarks/release/plan.json \
  --raw /absolute/new/path/release-raw.jsonl \
  --manifest /absolute/new/path/release-manifest.json \
  --output /absolute/new/path/release-summary.json
```

Run the same controller command with `--smoke` for a two-to-four sample local
check. Smoke output is marked `gate_eligible=false`; its summary is always
`INCONCLUSIVE` and is never release evidence.

The controller privately copies and hashes both binaries, validates exact
`--version` output, validates every workload before warmup and timing, and
publishes only to absent paths. It records per-process latency, status, output
count and digest, user/system CPU when the host exposes it, Linux peak RSS, and
Windows peak working set when the native API is available. The manifest records
the exact arguments as executed, the deliberately minimal environment,
artifact identities and sizes, platform, interpreter, source commit, counts,
and evidence hashes. A child timeout kills the owned child. Helper TCP and UDP
sockets are bounded, non-inheritable, IPv4/IPv6 loopback sockets and are closed
on every exit path.

Only `list --json` is compared with v1.2.0. Snapshot, Why, and the stable 500 ms
watch are candidate-only absolute-budget checks because v1.2.0 does not support
those commands. Reports explicitly set `comparison_supported=false` for them;
they must not be described as baseline improvements or regressions.

The final list, snapshot, and Why workloads retain at least ten blocks of 1,000
process samples. Each block receives 12 or 16 unmeasured warmups and comparison
blocks are exactly balanced from the recorded seed. The stable watch uses 2,000
process-level samples in ten bounded blocks.
The summarizer validates schema, all declared bounds and counts, deterministic
order, plan/raw/artifact hash consistency, and complete manifests before merging
raw observations. It computes nearest-rank p50/p95/p99/max and block-p99 range
from raw values, never averages percentiles, and reports latency, CPU, memory,
size, failures, thresholds, A/A noise, deltas, and `PASS`, `FAIL`, or
`INCONCLUSIVE`.

Run the unit tests with:

```sh
python3 -m unittest benchmarks.release.test_release_benchmark
```
