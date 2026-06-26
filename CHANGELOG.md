# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Windows TUI/CLI termination now separates user intent from the underlying
  delivery mechanism: lowercase `x` / non-`--force` is a normal termination
  request with `y` confirmation, while uppercase `X` / `--force` keeps the
  stronger typed `force` confirmation. Windows still delivers both through
  `TerminateProcess` because Kickoutchi does not have a reliable graceful
  process-handle equivalent; the confirmation copy and project notes now state
  that plainly instead of making lowercase `x` look like an accidental force key.
- The Windows protected-process defaults now include core Windows process names
  such as `System`, `svchost.exe`, `services.exe`, `lsass.exe`, `wininit.exe`,
  and Docker/Postgres `.exe` variants. The system/service classifier also treats
  PID 4, known Windows OS process names, and children of `services.exe` as
  system/service rows for warning and optional hiding.
- CLI kill now performs a best-effort post-kill port refresh after a successful
  termination and reports whether the confirmed target ports are still visible,
  instead of only telling the user to refresh manually.

- Linux termination now opens a pidfd before the mandatory pre-signal
  revalidation and sends `SIGTERM`/`SIGKILL` through `pidfd_send_signal` instead
  of raw `kill(pid, signal)`. This keeps the signal tied to the prepared process
  handle after the PID/start-time/port checks pass. It raises the floor for
  termination to Linux 5.3+ (`pidfd_open`); older kernels fail closed with an
  actionable error that names the requirement, without sending a signal.
- TUI refresh now uses a single in-flight background worker instead of running
  the full Linux `/proc/<pid>/fd` owner scan on the render/input loop. The last
  good snapshot remains visible while refresh is running. The first snapshot is
  still collected synchronously so the TUI opens onto real rows instead of a
  blank table, and any in-flight background refresh is abandoned when a
  synchronous snapshot (such as the post-kill refresh) is applied, so a stale
  scan cannot overwrite newer rows.
- Safe termination now carries an internal Linux process-start identity from
  `/proc/<pid>/stat` through confirmation and pre-signal revalidation. The raw
  tick value is not rendered or serialized, but it lets Kickoutchi refuse a kill
  if PID reuse is detected before the signal boundary.
- Post-Phase-6 internal cleanup, no external behavior change: collapsed the
  duplicate `KillTarget` constructor into a single `from_entries`, switched the
  confirmation modal's force-mode check from a signal-label string comparison to
  `KillMode` equality, and narrowed `current_user_id` to private.
- Comment accuracy, no behavior change: `PortEntry.child_pids` is now documented
  as a reserved field that stays empty on real rows (the Linux collector never
  fills it; selected-row children live in `ProcessContext`, and it remains only
  for the `list --json` shape and the fake fixture); the already-exited TUI kill
  test no longer describes the removed "refreshed snapshot" status wording; and
  `parse_process_start_time_ticks` now explains why it right-splits on `") "` so
  an unescaped `)` inside `comm` cannot be mistaken for the field terminator.
- The `KillTarget` construction invariants are now release assertions instead of
  debug-only ones: the target must contain at least one row, and every row's PID
  must match the target PID. A future caller that builds a kill target from no
  rows, or from rows owned by another PID, now fails fast on the termination path
  instead of carrying a degenerate, port-less, or mis-targeted target forward.
- Linux collector owner resolution now only records owners for socket inodes
  found in the collected `/proc/net/*` rows. It keeps every PID that references a
  target socket inode, so forked or inherited listening sockets are represented
  as multiple candidate owners instead of being collapsed to whichever PID was
  scanned first.
- Linux collector now reads `/proc/<pid>/status` through a byte-bounded reader,
  matching the existing cap on `/proc/<pid>/cmdline`, so every `/proc` read in the
  collector is explicitly limited; `PPid` sits near the top of `status`, so the
  cap never truncates the parent PID.
- TUI/CLI query matching now normalizes text filter needles once per query and
  avoids formatting socket-address strings unless the search text is
  socket-shaped, reducing per-keypress allocations in search mode.
- Removed the unused direct `anyhow` dependency from `Cargo.toml`; typed module
  errors remain the current error boundary.
- No-match port related-process diagnostics now use stricter rules that keep the
  main table limited to OS-confirmed sockets, preserve CLI exit codes, avoid
  polluting JSON output, and require port-shaped matchers instead of raw
  substring matching.
- `protected_processes` in the config file now extends the built-in defaults
  instead of replacing them, with exact-match de-duplication. Adding `redis`
  no longer silently removes protection from `systemd`, `postgres`, and the
  other defaults; this matches the documented "can be extended in config"
  behavior.
- Internal restructure: shared application code moved from `src/main.rs` to
  `src/lib.rs` (public surface: a single `kickoutchi::run()`), with thin
  binary wrappers in `src/bin/kickoutchi.rs` and `src/bin/kick.rs`. Behavior
  is unchanged; the shared code now compiles once for both binaries, unit
  tests no longer run twice, and the duplicate-target Cargo warning is gone.

### Fixed

- Windows termination liveness check now uses `WaitForSingleObject(handle, 0)`
  instead of comparing `GetExitCodeProcess` against `STILL_ACTIVE`, removing
  the ambiguity where exit code 259 was indistinguishable from "still running".

- Protected-process confirmation now compares user input against the
  sanitized process name, so what the prompt displays is exactly what the
  user must type (PID fallback still works).

- Windows TUI Caps Lock behavior no longer turns an intended lowercase `x` into
  force-kill. The force-kill key now requires an explicit Shift-modified `X`, so
  a Caps Lock uppercase `X` stays on the normal termination path.
- Typed force confirmation now accepts `force` case-insensitively, so `FORCE`
  does not trap users who entered the confirmation prompt with Caps Lock enabled.
- Protected-process confirmation now matches process names case-insensitively on
  Windows, matching Windows protected-name policy.
- Windows termination now waits briefly for a successful `TerminateProcess` call
  to complete before reporting success, reducing stale post-kill refreshes where
  a port can still appear immediately after the kill request.
- No-match related-process diagnostics now skip Kickoutchi's current process and
  its ancestors, avoiding false hints for the parent PowerShell/cargo command
  that launched `kick list --port <PORT>`.

- CLI `kill --yes` now prints the target banner — identity, ports, equivalent
  command, and any safety warnings (system/service process, ownership by another
  uid, partial metadata, child processes) — to stderr before signalling, instead
  of showing them only on the interactive confirmation path. `--yes` opts out of
  the prompt, not the warnings; the protected-process and unsafe-PID gates are
  unchanged, and stdout and exit codes are untouched so scripts are unaffected.
- TUI kill status lines now report only the signal outcome instead of also
  claiming a refreshed snapshot before the post-kill re-collect has run. The freed
  port still drops from the table via the best-effort refresh, but a failed
  re-collect surfaces as the usual error line rather than a status that overstates
  a refresh that did not happen.
- TUI header now lists `x/X kill` so the force-kill key is discoverable from the
  main screen, matching the input handling and the help modal.
- TUI termination now re-collects the port snapshot when a target exits between
  confirmation and `pidfd_open`. The prepare-error already-exited path returned
  without re-collecting, leaving the freed port on the table for up to one refresh
  interval. Other prepare failures (permission denied, an old kernel) leave the
  process running, so the table is already current for them.
- Termination confirmations now warn when a target is classified as a
  system/service process, not only when it is on the protected-process list.
- Pre-signal revalidation now reports ownership unavailable if any confirmed
  target port becomes visible without a readable PID, including mixed cases where
  another confirmed port still has the original PID.
- No-match related-process diagnostics no longer treat colon-shaped incidental
  tokens such as `duration:3000ms` or `host:3000abc` as socket evidence.
- `kill --port` now refuses inherited/shared listening sockets instead of
  signaling one arbitrary owner and reporting success while another process keeps
  the port open. The Linux collector emits one row per PID referencing the same
  socket inode, which lets the existing ambiguous-target guard list every
  candidate and require `--pid`.
- `kill --port` on a visible port whose owning PID is unavailable now exits with
  the documented permission-denied code `4` instead of the no-match code `3`,
  including when ownership becomes unavailable during the mandatory pre-signal
  revalidation.
- `kill --pid` now matches `kill --port` and the TUI when a confirmed target port
  stays visible but its owning PID becomes unreadable during pre-signal
  revalidation: it exits with the permission-denied code `4` instead of the
  no-match code `3`, and still sends no signal. A shared ownership-unavailable
  check now backs all three paths so they cannot drift.
- TUI pre-signal revalidation now reports an owner whose PID became unreadable as
  ownership-unavailable, matching the CLI, instead of labelling it a changed
  target; both still refuse to send a signal.
- Removed the stale `#[allow(dead_code)]` from `ExitReason`; every variant is
  now constructed by the CLI exit path, so the lint suppression would have
  hidden genuinely unreachable variants in future refactors.
- TUI `Esc` no longer quits when a filter is still applied after search editing
  finished: with no modal open and a non-empty filter, `Esc` now clears the
  filter and only quits on a second press once nothing is left to clear. An open
  modal still takes precedence. Previously, pressing `Enter` to finish a search
  and then reflexively pressing `Esc` ended the session instead of dropping the
  filter.
- TUI auto-refresh now schedules the next refresh from collection completion
  time instead of collection start time, avoiding an immediate repeat refresh
  when a slow `/proc` scan takes longer than the configured interval.
- CLI `list` now prints `no open ports visible` when `hide_system_processes`
  suppresses every collected row, instead of implying the machine has no open
  ports at all.
- TUI help modal title now reads `Kickoutchi` instead of an outdated
  phase-specific title.
- TUI status bar, borders, titles, and muted text now use terminal-default or
  bold-reversed styles instead of fixed dark-gray/black combinations, so the
  interface remains readable in both light and dark terminal themes.
- Linux collection no longer fails the whole scan when optional IPv6 socket
  tables such as `/proc/net/tcp6` or `/proc/net/udp6` are absent; IPv4 socket
  tables remain required.
- IPv4-mapped IPv6 socket addresses such as `::ffff:127.0.0.1` are normalized
  or classified as IPv4 loopback/local addresses instead of being mislabeled as
  generic local IPv6 binds.
- Terminal-state leak on TUI startup errors: a failure between enabling raw
  mode and constructing the terminal (entering the alternate screen, or the
  terminal's initial size query) now restores the terminal before the error
  propagates, instead of leaving the shell stuck in raw mode. Clean exits,
  propagated errors after startup, and panics were already covered by the
  guard and panic hook; this closes the remaining error window during setup.

### Added

- Native macOS support: `kickoutchi`/`kick` now lists TCP listeners and bound UDP
  sockets through `libproc` / `sysctl`, enriches rows with process metadata when
  available, uses start-time-guarded single-PID `SIGTERM` / `SIGKILL`
  termination, and renders macOS equivalent commands as `kill <PID>` or
  `kill -9 <PID>`. The default macOS path has no `lsof` dependency.
- macOS validation coverage now includes Darwin socket/procargs unit tests,
  a macOS-only CLI listener/interactive-kill smoke test, a GitHub Actions macOS
  job, and `mise` tasks for Linux-hosted Darwin `cargo check` / strict Clippy
  runs on both `x86_64-apple-darwin` and `aarch64-apple-darwin`.

- Human-display sanitizer that strips control characters, newlines, and ANSI
  escape sequences from OS-provided process metadata before rendering it in
  CLI table output, TUI table/details/confirm modals, kill banners, and
  confirmation prompts. JSON output stays raw and structured.

- Short `kick` binary integration test verifying that `--help` reports
  `Usage: kick`, `--version` reports the canonical `kickoutchi` name, and
  `list --json` prints valid JSON.

- Windows CLI contract coverage now starts a real local TCP listener, verifies
  `list --port` sees it, confirms `kill --pid` interactively with `y`, waits for
  the helper to exit, and verifies the port disappears. This complements the
  existing Windows unit coverage for IP Helper row normalization and Windows
  termination error mapping.

- `mise.toml` now includes local task aliases for formatting, strict Clippy,
  tests, the combined CI-equivalent check, and common `run`/`list` commands.
- Linux `/proc/<pid>/stat` start-time parsing is now tested for a `comm` that
  contains `) `, pinning the right-split that keeps the parse robust against
  unescaped parentheses in the process name.
- Linux CLI contract coverage now includes a real `SIGTERM` path: a controlled
  helper process binds a TCP listener, `kickoutchi kill --pid --yes` terminates
  it, and a follow-up list confirms the port disappears.
- TUI confirmed-kill execution is now covered with injected collection/context/
  termination seams, including successful refresh and stale process-identity
  refusal without sending a signal.
- GitHub Actions CI now runs on Linux pushes and pull requests, using the pinned
  Rust toolchain to check formatting, strict Clippy, and the full test suite.
  Release/CD automation remains deferred to the dedicated `cargo-dist` workflow.
- CLI contract integration tests now exercise script-facing `list` behavior with
  the real binary: human no-match diagnostics go to stderr, `list --json` stays
  unpolluted, and explicit no-match filters exit `3`. The helper process uses
  `sh`, so the suite needs no Python (or any other interpreter) on PATH.

- Safe termination MVP: Linux `kill` now sends real `SIGTERM` or
  `SIGKILL` through a small `libc` boundary instead of shelling out, with typed
  outcomes for success, permission denied, already exited, cancelled, protected
  process, stale confirmed target, unsafe PID, and unknown failure. Real signal
  delivery is Linux-only until native non-Linux collectors exist.
- Shared kill command rendering in `command.rs` shows the equivalent user-facing
  command (`kill <PID>`, `kill -9 <PID>`, or future platform equivalents) in both
  CLI and TUI confirmation flows.
- CLI `kickoutchi kill --pid <PID>` and `kickoutchi kill --port <PORT>` now use
  the same safety rules as the TUI: PID `0`, PID `1`, and Kickoutchi's own PID
  are blocked; protected processes require typing the PID or process name;
  `--yes` cannot bypass protected-process confirmation; and `kill --port`
  refuses ambiguous targets instead of guessing. After confirmation, the target
  is re-collected and must still match the confirmed PID and port rows before a
  signal is sent.
- TUI termination flow: `x` opens normal termination confirmation, `X` opens
  force-kill confirmation, force kill requires typing `force`, protected
  processes require typing the PID or process name, child/owner/permission
  warnings are shown when available, and the table refreshes immediately after a
  kill attempt.
- Safe-termination tests cover PID guardrails, target ambiguity, confirmation decisions,
  command rendering, TUI confirmation state/rendering, and CLI exit-code mapping.
- TUI kill confirmation now lists every port owned by the target PID, gathered
  from the full snapshot so active filters cannot hide a port the signal will
  still free.

- Process context and protected-process policy: the selected TUI row
  now resolves direct child PIDs and child process names only when the user opens
  the details modal, shows owner UID when available, and keeps the child scan
  bounded so scrolling the table does not walk the process list.
- Protected-process matching now lives in `protection.rs`, with exact
  case-sensitive matching on Unix-like platforms and exact case-insensitive
  matching ready for Windows.
- No-match port diagnostics for human CLI output: when an explicit port query
  finds no confirmed listening TCP or bound UDP socket, Kickoutchi can print
  evidence-only related-process hints to stderr based on strict port-shaped
  command-line matches such as `:3000`, `--port 3000`, `--port=3000`, `-p 3000`,
  `PORT=3000`, and `python3 -m http.server 3000`.
- Diagnostic hints do not create fake table rows, do not claim ownership, do not
  change the `list --port` no-match exit code, and do not pollute `list --json`.

- Filtering, sorting, and refresh: the TUI now supports manual
  refresh with `r`, automatic refresh using the configured interval, search mode
  with `/`, and sort cycling with `s`.
- Shared query engine for CLI and TUI filtering: plain search matches visible
  row fields such as port, PID, protocol, address, process name, executable
  path, command line, bind scope, and parent process; structured filters support
  `pid:`, `port:`, `proto:`, `scope:`, `protected:`, and `parent:`.
- Additional sort modes for parent process and bind scope, with scope sorting
  surfacing public binds before local and loopback binds.
- Linux parent-process collection backing the parent filter and sort: `parent_pid`
  from `/proc/<pid>/status` and the parent name from `/proc/<ppid>/comm`, feeding
  the `parent:` filter, parent sorting, the details-panel parent line, and PID-1
  child hiding. Implemented alongside filtering and sorting so the parent filter
  and sort operate on real data instead of always-empty fields.
- TUI refresh state now keeps the last successful snapshot separate from the
  latest collector error, so a failed refresh reports the error without erasing
  the last good table.
- Selection preservation across refresh/filter/sort by PID, protocol, local
  address, and port, falling back to the nearest sensible row when the selected
  process disappears.
- `kickoutchi list --filter <TEXT>` and `kickoutchi list --sort <MODE>` for the
  same search/filter/sort behavior used by the TUI.
- Config support for `hide_system_processes`, implemented conservatively for
  PID 0/1, direct PID-1 children, and known OS process names without hiding
  protected app processes such as `postgres` by default.

- Linux native collector: on Linux, `kickoutchi`/`kick` now reads
  `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6`
  directly, keeps TCP `LISTEN` sockets and bound UDP sockets, decodes IPv4 and
  IPv6 local addresses, extracts socket inodes, and maps them to owning PIDs by
  walking `/proc/<pid>/fd` symlinks.
- Linux process metadata enrichment: readable owners now include process name,
  executable path, and command line from `/proc/<pid>/comm`, `/proc/<pid>/exe`,
  and `/proc/<pid>/cmdline`; restricted or raced metadata keeps the port row and
  marks it partial instead of dropping it.
- Deterministic Linux collector tests for `/proc/net` parsing, TCP state filtering, UDP
  bound rows, IPv4/IPv6 decoding, malformed rows, socket inode parsing,
  command-line decoding, and partial metadata behavior.

- Static TUI skeleton: the bare `kickoutchi`/`kick` command now opens
  a full fake-data TUI with a header, the open-ports table, a selected-row
  details panel, and a status bar showing row count, refresh age, sort mode,
  and filter state.
- TUI app state (`app.rs`) and key-to-action input mapping (`input.rs`):
  bounded `j`/`k`/Up/Down selection, `Enter` for a details modal, `?` for a
  help modal, `Esc` closing modals (or quitting when none is open), and rows
  marked protected and sorted through the same shared model code as the CLI.
- UI modules `table`, `details`, `help`, and `theme`: missing metadata renders
  as `-`, partial-permission and protected rows get distinct styling with the
  reason explained in the details panel, child PIDs distinguish "not loaded"
  from none, and `NO_COLOR` disables colors while keeping non-color emphasis.
- Terminal-size fallback message when the viewport is smaller than 80x20.
- Render tests over a ratatui `TestBackend` (default frame, help modal,
  details modal, too-small fallback) plus app-state transition tests for
  selection bounds, modal flow, and empty-row behavior.

- Short binary name `kick`: the crate now installs both `kickoutchi`
  (canonical) and `kick` (short alias for CLI use) from the same source, with
  `default-run` keeping `cargo run` on the canonical binary. The help usage
  line follows the invoked name; `--version` reports the canonical name.

- Shared domain model: `PortEntry` with the full
  protocol/address/port/state/process/parent/permission shape, plus the
  `Protocol`, `SocketState`, `Platform`, `PermissionStatus`, and `SortMode`
  vocabulary shared by the CLI, TUI, and future collectors.
- `Collector` trait with a deterministic `FakeCollector` covering full
  metadata, permission-restricted partial rows, IPv6, bound UDP, and a
  default-protected process name.
- Config file support: `~/.config/kickoutchi/config.toml` (XDG via `dirs`)
  with `refresh_interval_seconds`, `default_sort`, `confirm_force_kill`, and
  `protected_processes`; missing file means safe defaults, invalid file is a
  hard error naming the file and the bad value; bounded values and a capped
  protected list.
- Non-TUI CLI: `kickoutchi list` (`--port`, `--process`, `--json`) and the
  `kickoutchi kill` command shape (`--pid`/`--port`, `--force`, `--yes`) with
  confirmation prompts routed to a stub until real termination lands; CLI
  commands never open the TUI.
- Stable script-facing exit codes (0–6) defined and tested in one place;
  `--yes` never bypasses the protected-process path (exit 6).
- CLI-over-config precedence via global `--config <FILE>` and
  `--refresh-interval <SECONDS>` flags, with shared bounds enforced by clap at
  parse time.
- Table and JSON output layer; missing metadata renders as `-` in tables and
  `null` in JSON, and the JSON field/enum shape is pinned by tests.
- Cargo manifest metadata (`description`, `license`, `repository`, `authors`,
  `readme`) required for later `cargo publish`/`cargo-dist` release work.
- Project foundation: Rust 1.95.0 pinned via `mise.toml`, edition
  2024, and strict lints (`warnings = "deny"`, `clippy::pedantic`).
- Core dependency set: ratatui, crossterm, clap, serde, serde_json, toml,
  thiserror, anyhow, tracing, and tracing-subscriber.
- Module boundaries: `main`, `config`, `error`, and `ui`.
- Safe terminal lifecycle: an RAII `TerminalGuard` that enters raw mode and the
  alternate screen and restores both on drop (clean exit, propagated error, or
  panic), plus a panic hook that restores the terminal before the message prints.
- Minimal event loop with a bounded poll that quits on `q`, `Esc`, or `Ctrl+C`.
- `tracing` diagnostics routed to stderr only, never the TUI surface.
- Unit tests for the quit predicate, including the key-release edge case.

[Unreleased]: https://github.com/nuggocto/kickoutchi/commits/shrek
