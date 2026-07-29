# Performance snapshot

This snapshot compares the published v1.3.8 source
(`95c4548d57b61fb7a071f1cbc3c35eae0ccabe21`) with unreleased implementation
commit `b4af784f270d7ddb8a4cc4c5b783a0558627dc8e`. Later commit `cf38db2` changed
only the benchmark report, so `b4af784` is also the implementation at the time
of this measurement.

Verdict: no meaningful performance regression was measured. All four workloads
in each of the three independent sessions remained within the predeclared noise
and practical-change thresholds. The result is directional evidence from one
Linux workstation, not a cross-platform performance guarantee.

## Wall time

Each percentile combines 3,000 observations for that build and workload. The
p99 is the nearest-rank value, so it represents the 30th-slowest observation.
Measured maxima are included as diagnostics, not as stable upper bounds.

| Workload | Build | p50 | p90 | p95 | p99 | Maximum |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Cold startup | v1.3.8 | 1.145 ms | 1.171 ms | 1.182 ms | 1.218 ms | 1.436 ms |
| Cold startup | `b4af784` | 1.145 ms | 1.170 ms | 1.182 ms | 1.222 ms | 1.428 ms |
| Warm startup | v1.3.8 | 1.146 ms | 1.175 ms | 1.185 ms | 1.216 ms | 1.309 ms |
| Warm startup | `b4af784` | 1.146 ms | 1.174 ms | 1.184 ms | 1.215 ms | 1.296 ms |
| `list` | v1.3.8 | 12.804 ms | 17.338 ms | 19.120 ms | 21.605 ms | 40.527 ms |
| `list` | `b4af784` | 12.799 ms | 17.156 ms | 18.466 ms | 22.435 ms | 40.410 ms |
| `list --json` | v1.3.8 | 12.776 ms | 17.052 ms | 18.086 ms | 21.339 ms | 42.362 ms |
| `list --json` | `b4af784` | 12.774 ms | 17.106 ms | 18.137 ms | 21.275 ms | 39.468 ms |

| Workload | Candidate p50 delta | p90 delta | p95 delta | p99 delta |
| --- | ---: | ---: | ---: | ---: |
| Cold startup | 0.00% | -0.08% | -0.02% | +0.27% |
| Warm startup | 0.00% | -0.07% | -0.08% | -0.09% |
| `list` | -0.04% | -1.05% | -3.42% | +3.84% |
| `list --json` | -0.02% | +0.32% | +0.28% | -0.30% |

The three per-session p99 ranges were 1.210–1.237 ms for candidate startup,
16.056–22.888 ms for candidate `list`, and 16.049–22.166 ms for candidate
`list --json`. That visible host-state variation is why the conclusion uses
interleaving and predeclared thresholds instead of treating a single percentile
delta as a regression.

## CPU and peak RSS

CPU time is child user plus system time reported by `wait4`. Linux peak RSS is
also reported per child by `wait4`.

| Workload | Build | CPU p50 | p90 | p95 | p99 | Maximum |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Cold startup | v1.3.8 | 0.319 ms | 0.454 ms | 0.542 ms | 0.658 ms | 1.216 ms |
| Cold startup | `b4af784` | 0.320 ms | 0.450 ms | 0.542 ms | 0.641 ms | 1.043 ms |
| Warm startup | v1.3.8 | 0.309 ms | 0.503 ms | 0.554 ms | 0.663 ms | 0.993 ms |
| Warm startup | `b4af784` | 0.309 ms | 0.524 ms | 0.556 ms | 0.641 ms | 0.880 ms |
| `list` | v1.3.8 | 12.083 ms | 16.608 ms | 18.055 ms | 20.855 ms | 39.814 ms |
| `list` | `b4af784` | 12.115 ms | 16.450 ms | 17.761 ms | 21.370 ms | 39.863 ms |
| `list --json` | v1.3.8 | 11.947 ms | 16.079 ms | 17.113 ms | 20.391 ms | 41.937 ms |
| `list --json` | `b4af784` | 11.921 ms | 16.135 ms | 17.181 ms | 20.256 ms | 38.269 ms |

Peak-RSS percentiles were identical between the two builds:

| Workload | p50 | p90 | p95 | p99 / maximum |
| --- | ---: | ---: | ---: | ---: |
| Cold startup | 22,700 KiB | 23,156 KiB | 23,156 KiB | 23,412 KiB |
| Warm startup | 23,924 KiB | 24,436 KiB | 24,436 KiB | 24,948 KiB |
| `list` | 25,004 KiB | 25,716 KiB | 25,972 KiB | 25,972 KiB |
| `list --json` | 26,228 KiB | 26,540 KiB | 26,540 KiB | 26,540 KiB |

## Snapshot artifact size and correctness

| Artifact | v1.3.8 | Candidate | Delta |
| --- | ---: | ---: | ---: |
| `kickoutchi` binary | 4,040,984 B | 4,046,488 B | +5,504 B (+0.14%) |
| Linux `.tar.xz` | 1,321,544 B | 1,322,736 B | +1,192 B (+0.09%) |

After the latency snapshot, the 1.3.9 distribution profile began stripping
symbol tables while explicitly retaining panic unwinding. The production
profile build preserved the same executable code sections and reduced the
artifacts as follows:

| Artifact | Pre-strip candidate | 1.3.9 stripped | Net delta |
| --- | ---: | ---: | ---: |
| Each Linux executable | 4,046,488 B | 3,289,136 B | -757,352 B (-18.72%) |
| Linux `.tar.xz` | 1,322,736 B | 1,173,352 B | -149,384 B (-11.29%) |

The archive comparison is a net release-candidate result and includes the
updated README and changelog, not a synthetic recompression of identical
contents. Both stripped aliases reported `kickoutchi 1.3.9`; the canonical
binary also emitted valid top-level-array JSON.

All 24,000 timed processes exited with status zero and none timed out. Before
each session, both builds also passed bounded correctness probes: `--version`
reported `kickoutchi 1.3.8`, human `list` output lengths matched, and
`list --json` produced a top-level array with matching output lengths. Output
lengths changed between sessions as the live process table changed, but matched
between builds within every session.

## Environment

- Date: 2026-07-29.
- CPU: AMD Ryzen AI Max+ 395, 16 cores / 32 threads, boost enabled.
- Memory visible to the environment: 62.1 GiB.
- CPU scaling governor: `performance`; no CPU affinity or scheduler isolation.
- Execution environment: managed container on the local host.
- OS: Arch Linux, Linux 7.1.4-arch1-1 x86_64, glibc 2.43.
- Toolchains: Rust/Cargo 1.95.0, cargo-dist 0.32.0, Python 3.14.4.
- One-minute load averages at session capture: 1.38, 1.56, and 1.08.
- Build: isolated `git archive` exports, `x86_64-unknown-linux-gnu`, all
  features, cargo-dist `dist` profile with thin LTO.

## Method

Three sessions used fixed seeds `1263092555`, `1263092556`, and `1263092557`.
Each session ran 1,000 interleaved observations per build for cold startup, warm
startup, `list`, and `list --json`, with five warmups and a 10-second
per-process deadline. Baseline and candidate order was shuffled deterministically
within each workload. `LC_ALL=C`, `NO_COLOR=1`, and an isolated empty
`XDG_CONFIG_HOME` kept configuration and presentation stable.

Cold startup runs invoked `--version` after applying
`POSIX_FADV_DONTNEED` to that executable's pages. No system-wide cache was
purged. Warm startup invoked the same command without eviction. The two list
workloads observed the same live host process state and did not terminate
processes, probe the network, or use Docker.

Wall time used `perf_counter_ns`; child CPU and peak RSS came from `wait4`.
The harness polled child completion at 1 ms intervals, which puts an artificial
floor on the very fast startup measurements. Startup values are therefore useful
for same-harness comparisons, not as precise claims about intrinsic sub-millisecond
runtime.

A latency change was classified as meaningful only when the paired median
exceeded all three predeclared thresholds: 5% of the baseline median, 0.25 ms
for startup or 0.50 ms for list workloads, and three scaled median absolute
deviations of the paired differences. The temporary dependency-free harness is
preserved in Git history at `cf38db2`; it is not retained in the working tree
because continuous shared-runner latency checks would add maintenance and noise
without improving a release gate.

Throughput and allocation counts were not measured. Kickoutchi is an
independently invoked CLI rather than a steady-state request service, and no
performance-sensitive regression was observed that justified profiling or
optimization. Windows, macOS, and other Linux hardware were not benchmarked.
