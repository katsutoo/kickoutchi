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
python3 -m unittest -v qa.test_release_qa
```
