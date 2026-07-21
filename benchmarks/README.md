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
python benchmarks/collect-watch-samples.py target/dist/kick 100 4 \
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
