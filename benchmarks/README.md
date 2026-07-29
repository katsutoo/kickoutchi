# Performance baseline

`run.py` compares two optimized Linux binaries on the same host. It measures
cold and warm startup, `list`, and `list --json` with fixed-seed interleaving so
machine drift affects the two builds as evenly as practical.

The harness records wall-time p50/p95/p99, CPU p50, peak-RSS p50/p95, binary and
optional package size, and every exit failure or timeout. Cold startup uses
`POSIX_FADV_DONTNEED` on only the benchmark binary before each run; it does not
purge system-wide caches. Warm cases receive bounded warmups. A latency change
is called meaningful only when its paired median exceeds all of:

- 5% of the baseline median;
- the case's fixed practical threshold (0.25 ms for startup, 0.50 ms otherwise);
- three scaled median absolute deviations of the paired differences.

Build both revisions with the same pinned Rust toolchain and profile, then run:

```console
python3 benchmarks/run.py \
  --baseline /tmp/kickoutchi-v1.3.8/target/dist/kickoutchi \
  --candidate /tmp/kickoutchi-candidate/target/dist/kickoutchi \
  --candidate-label <candidate-commit> \
  --samples 100 \
  --cold-samples 30 \
  --baseline-package /tmp/kickoutchi-v1.3.8.tar.xz \
  --candidate-package /tmp/kickoutchi-candidate.tar.xz \
  --json-output /tmp/kickoutchi-performance.json \
  --markdown-output /tmp/kickoutchi-performance.md
```

Full latency benchmarks stay manual or scheduled because shared CI runners are
too noisy for a required regression gate. Release archive validation retains
deterministic bounded-size checks independently of these comparative results.

Recorded baselines:

- [v1.3.8 versus candidate `b4af784`](results/2026-07-29-v1.3.8-vs-b4af784.md)
