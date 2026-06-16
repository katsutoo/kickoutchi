# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Post-Phase-6 internal cleanup, no external behavior change: collapsed the
  duplicate `KillTarget` constructor into a single `from_entries`, switched the
  confirmation modal's force-mode check from a signal-label string comparison to
  `KillMode` equality, and narrowed `current_user_id` to private.
- The `KillTarget` "at least one row" invariant is now a release assertion
  instead of a debug-only one, so a future caller that builds a kill target from
  no rows fails fast on the termination path instead of carrying a degenerate,
  port-less target forward.
- Linux collector owner resolution now only records owners for socket inodes
  found in the collected `/proc/net/*` rows, and stops scanning process file
  descriptors once every target inode has been matched. This reduces repeated
  auto-refresh work on noisy machines without changing output semantics.
- Linux collector now reads `/proc/<pid>/status` through a byte-bounded reader,
  matching the existing cap on `/proc/<pid>/cmdline`, so every `/proc` read in the
  collector is explicitly limited; `PPid` sits near the top of `status`, so the
  cap never truncates the parent PID.
- TUI/CLI query matching now normalizes text filter needles once per query and
  avoids formatting socket-address strings unless the search text is
  socket-shaped, reducing per-keypress allocations in search mode.
- Removed the unused direct `anyhow` dependency from `Cargo.toml`; typed module
  errors remain the current error boundary.
- Roadmap update: no-match port related-process diagnostics moved from Phase 4
  to Phase 5, with stricter rules that keep the main table limited to
  OS-confirmed sockets, preserve CLI exit codes, avoid polluting JSON output,
  and require port-shaped matchers instead of raw substring matching.
- `protected_processes` in the config file now extends the built-in defaults
  instead of replacing them, with exact-match de-duplication. Adding `redis`
  no longer silently removes protection from `systemd`, `postgres`, and the
  other defaults; this matches the documented "can be extended in config"
  behavior from PROJECT.md.
- Internal restructure: shared application code moved from `src/main.rs` to
  `src/lib.rs` (public surface: a single `kickoutchi::run()`), with thin
  binary wrappers in `src/bin/kickoutchi.rs` and `src/bin/kick.rs`. Behavior
  is unchanged; the shared code now compiles once for both binaries, unit
  tests no longer run twice, and the duplicate-target Cargo warning is gone.

### Fixed

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
- TUI help modal title now reads `Kickoutchi` instead of `Kickoutchi Phase 4`.
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

- GitHub Actions CI now runs on Linux pushes and pull requests, using the pinned
  Rust toolchain to check formatting, strict Clippy, and the full test suite.
  Release/CD automation remains deferred to the Phase 11 `cargo-dist` workflow.

- Safe termination MVP (Phase 6): Linux `kill` now sends real `SIGTERM` or
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
- Phase 6 tests cover PID guardrails, target ambiguity, confirmation decisions,
  command rendering, TUI confirmation state/rendering, and CLI exit-code mapping.
- TUI kill confirmation now lists every port owned by the target PID, gathered
  from the full snapshot so active filters cannot hide a port the signal will
  still free.

- Process context and protected-process policy (Phase 5): the selected TUI row
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

- Filtering, sorting, and refresh (Phase 4): the TUI now supports manual
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
  child hiding. Pulled forward from Phase 5 so the Phase 4 parent filter and sort
  operate on real data instead of always-empty fields.
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

- Linux native collector (Phase 3): on Linux, `kickoutchi`/`kick` now reads
  `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6`
  directly, keeps TCP `LISTEN` sockets and bound UDP sockets, decodes IPv4 and
  IPv6 local addresses, extracts socket inodes, and maps them to owning PIDs by
  walking `/proc/<pid>/fd` symlinks.
- Linux process metadata enrichment: readable owners now include process name,
  executable path, and command line from `/proc/<pid>/comm`, `/proc/<pid>/exe`,
  and `/proc/<pid>/cmdline`; restricted or raced metadata keeps the port row and
  marks it partial instead of dropping it.
- Deterministic Phase 3 tests for `/proc/net` parsing, TCP state filtering, UDP
  bound rows, IPv4/IPv6 decoding, malformed rows, socket inode parsing,
  command-line decoding, and partial metadata behavior.

- Static TUI skeleton (Phase 2): the bare `kickoutchi`/`kick` command now opens
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

- Shared domain model (Phase 1): `PortEntry` with the full
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
  `readme`) required for later `cargo publish`/`cargo-dist` phases.
- Project foundation (Phase 0): Rust 1.95.0 pinned via `mise.toml`, edition
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
