#!/usr/bin/env bash
set -euo pipefail

binary=${1:?"usage: collect-list-samples.sh BINARY [SAMPLES] [WARMUPS] [OUTPUT]"}
samples=${2:-200}
warmups=${3:-8}
output=${4:-/tmp/kickoutchi-list-latency.tsv}

if [[ ! -x "$binary" ]]; then
  printf 'benchmark binary is not executable: %s\n' "$binary" >&2
  exit 2
fi
if [[ ! "$samples" =~ ^[1-9][0-9]*$ || ! "$warmups" =~ ^[0-9]+$ ]]; then
  printf 'samples must be positive and warmups must be nonnegative\n' >&2
  exit 2
fi

mkdir -p "$(dirname "$output")"
{
  printf '# source_commit=%s\n' "$(git rev-parse HEAD)"
  printf '# source_dirty=%s\n' "$(test -n "$(git status --porcelain=v1)" && printf true || printf false)"
  printf '# artifact_sha256=%s\n' "$(sha256sum "$binary" | cut -d' ' -f1)"
  printf '# rustc=%s\n' "$(rustc --version)"
  printf '# kernel=%s\n' "$(uname -srmo)"
  printf '# warmups=%s\n' "$warmups"
  printf '# samples=%s\n' "$samples"
  printf 'sample\tlatency_ns\n'
} >"$output"

for ((run = 0; run < warmups; run++)); do
  "$binary" list --json >/dev/null
done

for ((run = 1; run <= samples; run++)); do
  started_ns=$(date +%s%N)
  "$binary" list --json >/dev/null
  completed_ns=$(date +%s%N)
  printf '%s\t%s\n' "$run" "$((completed_ns - started_ns))" >>"$output"
done

printf 'wrote %s successful samples to %s\n' "$samples" "$output"
