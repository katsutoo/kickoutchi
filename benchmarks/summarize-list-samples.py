#!/usr/bin/env python3
import os
import stat
import sys
from pathlib import Path
from typing import NoReturn

INPUT_BYTES_MAX = 16 * 1024 * 1024
SAMPLES_MAX = 100_000
LATENCY_NS_MAX = 35_000_000_000


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def read_bounded_regular_file(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"could not open sample file: {error}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"sample file is not a regular file: {path}")
        if metadata.st_size > INPUT_BYTES_MAX:
            fail(f"sample file exceeds {INPUT_BYTES_MAX} bytes")
        chunks = []
        retained = 0
        while chunk := os.read(descriptor, min(1024 * 1024, INPUT_BYTES_MAX + 1 - retained)):
            retained += len(chunk)
            if retained > INPUT_BYTES_MAX:
                fail(f"sample file exceeds {INPUT_BYTES_MAX} bytes")
            chunks.append(chunk)
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError:
            fail("sample file is not valid UTF-8")
    finally:
        os.close(descriptor)


if len(sys.argv) > 2:
    fail("usage: summarize-list-samples.py [INPUT]")

input_path = Path(
    sys.argv[1] if len(sys.argv) > 1 else "/tmp/kickoutchi-list-latency.tsv"
).resolve()
declared_samples: int | None = None
header_seen = False
latencies = []
failures = 0
count = 0

for line in read_bounded_regular_file(input_path).splitlines():
    if line.startswith("# samples="):
        if declared_samples is not None:
            fail("sample file declares its sample count more than once")
        value = line.removeprefix("# samples=")
        if not value.isascii() or not value.isdecimal():
            fail("declared sample count is invalid")
        declared_samples = int(value)
        continue
    if line == "sample\tlatency_ns\tstatus":
        if header_seen:
            fail("sample file contains its header more than once")
        header_seen = True
        continue
    if not line or line.startswith("#"):
        continue

    fields = line.split("\t")
    if len(fields) != 3 or any(not field for field in fields):
        fail("sample row does not have exactly three nonempty fields")
    if any(not field.isascii() or not field.isdecimal() for field in fields):
        fail("sample row contains a non-decimal field")
    sample, latency, status = map(int, fields)
    count += 1
    if count > SAMPLES_MAX:
        fail(f"sample count exceeds {SAMPLES_MAX}")
    if sample != count:
        fail(f"expected sample {count}, got {sample}")
    if latency > LATENCY_NS_MAX:
        fail(f"latency exceeds the bounded child duration for sample {sample}")
    if status > 255:
        fail(f"status is outside 0..=255 for sample {sample}")
    if status == 0:
        latencies.append(latency)
    else:
        failures += 1

if not header_seen:
    fail("sample file is missing its exact header")
if declared_samples is None or declared_samples != count:
    fail("declared sample count does not match measured rows")
if not latencies:
    fail("sample file contains no successful measurements")

latencies.sort()


def percentile(percent: int) -> int:
    index = (len(latencies) * percent + 99) // 100
    return latencies[index - 1]


print(
    f"samples={count} successes={len(latencies)} failures={failures} "
    f"p50_ns={percentile(50)} p95_ns={percentile(95)} "
    f"p99_ns={percentile(99)} max_ns={latencies[-1]}"
)
