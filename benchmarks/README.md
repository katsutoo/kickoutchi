# Benchmark Protocol

Benchmark exact release-profile artifacts, never `cargo run` or debug builds.
The Stage 2 feasibility check uses `list --json` as a conservative end-to-end
collection workload until the snapshot/watch commands exist.

Build and collect raw samples with:

```sh
cargo build --locked --profile dist --all-features --bin kickoutchi --bin kick
benchmarks/collect-list-samples.sh target/dist/kick 200 8 \
  /tmp/kickoutchi-list-latency.tsv
```

The script records one successful child-process invocation per row in
nanoseconds and writes environment, source, and artifact identifiers as comment
lines. Keep the raw TSV in an immutable CI artifact or attach it to the stage
review. Do not cite results whose raw file is unavailable.

For the Stage 2 gate, record the workload's process, descriptor, socket, and row
counts; machine CPU/RAM; OS/kernel; Rust version; power state; concurrent load;
artifact SHA-256; warmups; sample count; p50/p95/p99/max; failures; and peak RSS.
Compare the measured tail against the predeclared 100 ms watch floor. This is a
feasibility decision, not a cross-machine performance promise.

The final release benchmark must additionally interleave baseline and candidate
artifacts under the same live or synthetic workload and preserve its ordering
seed and all raw samples.
