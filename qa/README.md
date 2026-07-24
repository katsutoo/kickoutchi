# Extracted Release QA

Run the standard-library-only exploratory harness against both binaries from one
extracted release archive:

```sh
python3 -m qa.release_qa \
  --canonical /absolute/path/to/kickoutchi \
  --short /absolute/path/to/kick \
  --candidate-commit 40-lowercase-hex-characters \
  --archive-sha256 64-lowercase-hex-characters \
  --output /absolute/path/to/release-qa.json
```

The output path must not exist. Both binary paths must be explicit, regular,
nonempty, executable files no larger than 512 MiB. Every product process has a
deadline and bounded stdout/stderr capture. The harness uses an isolated home,
configuration directory, temporary directory, and explicit config path.

The JSON report records binary hashes, host/tool context, exact product commands,
bounded result metadata and stream digests, harness-owned listener PIDs and
sockets, cleanup evidence, and a status for every check. Captured stream contents
and the unique privacy marker are redacted before publication. `BLOCKED`
identifies a missing harness/platform capability rather than a product failure
and returns a nonzero status. On Windows, install `windows-tui-requirements.txt`
with hash checking, run `windows_tui_smoke.py` first, and
pass its JSON through `--windows-tui-evidence`; the harness validates the
artifact hash, ConPTY console lifecycle, terminal restoration, exit status, and
stream bounds before accepting that check.

Run focused harness tests with:

```sh
python3 -m unittest -v qa.test_release_qa qa.test_extended_release_qa
```

## Extended charters

Run the additional upgrade, endpoint-matrix, watch-lifecycle, input-boundary,
termination, and platform-scope charters with an extracted v1.2 executable and
the exact candidate executable:

```sh
python3 -m qa.extended_release_qa \
  --candidate /absolute/path/to/v1.3/kickoutchi \
  --candidate-sha256 64-lowercase-hex-characters \
  --baseline /absolute/path/to/v1.2/kickoutchi \
  --baseline-sha256 64-lowercase-hex-characters \
  --candidate-commit 40-lowercase-hex-characters \
  --output /absolute/path/to/extended-release-qa.json
```

The output path must not exist. Both executable hashes are mandatory and are
checked before either artifact runs. All product commands have bounded output
and deadlines. Configurations, sockets, listeners, process trees, process
groups, fault state, and compiler output live in the harness-owned temporary
tree and are cleaned up on every exit path. Cleanup uncertainty makes the report
inconclusive.

The deterministic collection-failure charter is Linux-only. It builds the
QA-owned `watch_fault_fixture.c` interposer with `cc` inside the temporary tree
and fails selected `/proc/net/tcp` opens; a missing compiler blocks that charter
rather than weakening it. Tree termination runs on Linux, macOS, and Windows;
process-group termination runs on Linux and macOS. Unsupported IPv6 is retained
as an explicit Why result. The Windows charter asserts the native-host scope and
`wsl_network_stack_excluded` contract and records actual WSL capability probes;
it does not claim that the Windows artifact executed inside WSL.

The release qualification workflow downloads and verifies the published v1.2
artifact for each native target, passes both executable hashes, runs this module,
uploads its report, and requires `overall: PASS`.
