# Kickoutchi Process Tree Plan

This plan tracks Kickoutchi's scoped process cleanup work. Linux/macOS scoped
kill shipped cleanly in `1.0.0`; the next implementation phase is Windows
scoped cleanup, shipping as a single combined `1.1.0` release that adds Windows
CLI `--tree` and read-only `inspect` together. `--group` stays Unix-only —
process groups are a POSIX concept with no Windows analog.

Normal `kick kill` must stay precise: it terminates only the confirmed PID. Tree
and group kill are the big ogre buttons, and they must stay clearly opt-in.

Status decision: Linux and macOS are done for `1.0.0`: CLI `--tree`, CLI
`--group`, read-only `inspect`, and TUI `t`/`T` tree kill are implemented and
verified. Windows still intentionally exposes only listing and safe
single-process kill; Windows scoped cleanup is next, shipped as one combined
`1.1.0` (CLI `--tree` + `inspect`) using the job-containment design below. A
real Windows machine is now available for the interactive QA that phase
requires, so the deferral is scheduling, not a QA-access blocker.

## Current Status

- `1.0.0` Linux/macOS scoped cleanup is clear and clean: implemented, tested,
  cross-target checked, packaged, and documented.
- Normal process kill remains unchanged and precise.
- `--tree` and TUI `t`/`T` are Linux/macOS-only descendant-tree cleanup.
- `--group` is Linux/macOS-only CLI process-group cleanup.
- `inspect` is Linux/macOS-only, read-only family/group inspection.
- Windows scoped cleanup is the next phase, shipped as one combined `1.1.0`:
  CLI `--tree` and read-only `inspect`, delivered together. `--group` stays
  Unix-only. It must not copy the Unix freeze-first wording because Windows has
  no supported `SIGSTOP` equivalent.

## Problem

AI agents, dev servers, package runners, shell wrappers, and file watchers often
leave behind child processes. Killing only the port-owning PID can leave workers,
bundlers, shells, or detached helpers alive. Users then end up hunting processes
by hand or rebooting.

The motivating scenario (the "Dax situation"): a buggy process that keeps
spawning children faster than you can kill them. This is the case that forces
reboots, and it is also the case a naive "enumerate the tree, then kill the
list" implementation loses: the spawner forks new children between your
enumeration and your signals, you kill the snapshot, and the survivors respawn.
The design below is built around not losing that race.

Bun has a related `noOrphans` feature for processes it spawned: on exit, it can
recursively kill descendants so nothing it launched survives unexpectedly. That
model is useful, but Kickoutchi is different. Bun controls the lifetime of the
processes it spawns (it can put them in process groups it created and hold their
handles from birth). Kickoutchi targets arbitrary processes already running on
the machine, so it can rely on none of that: it must require stronger consent,
verify identity at every step, and use freezing to make enumeration trustworthy.

### What 1.0 solves, and what it honestly does not

- `1.0.0` solves the common Linux/macOS cases: a dev server, agent, or runner
  left a bounded tree of workers behind; a worker reparented away from the
  descendant tree but stayed in the process group; or the user needs to inspect
  ancestors before choosing the right root.
- `1.0.0` does **not** solve Windows tree/group cleanup yet. That is next.
- `1.0.0` still refuses instead of partially killing an over-cap or
  non-converging scope. Partial kills of a moving target are worse than
  refusing: they report false progress while the swamp regrows.

## Non-Goals

- Do not change the default behavior of `kick kill`.
- Do not silently kill children just because a target has them.
- Do not add a new dependency for process walking. The standard library,
  `libc`, and the existing platform scan primitives are sufficient (verified:
  the enumeration data already exists in `linux.rs` and `macos.rs`).
- Do not implement automatic ancestor cleanup. `inspect` shows ancestors so the
  user can choose an explicit root PID; killing upward must never be automatic.
- Do not pretend Windows has Unix freeze semantics. Windows scoped cleanup must
  use honest job-containment wording and a separate execution path.

## User-Facing Shape

Linux/macOS scoped cleanup:

```sh
kick kill --port 3000 --tree
kick kill --pid 12345 --tree
kick kill --port 3000 --tree --force
kick kill --pid 12345 --group
kick inspect --port 3000
kick inspect --pid 12345
```

Default behavior remains:

```sh
kick kill --port 3000
kick kill --pid 12345
```

TUI tree cleanup is implemented on Linux/macOS: `t` terminates the selected
process tree and `T` force-kills it, mirroring `x`/`X` and preserving Caps Lock
handling. Process-group cleanup stays CLI-only in `1.0.0` because the full
group member list belongs in an explicit CLI banner.

## Safety Contract

Tree kill must follow these rules:

- The user must explicitly request tree scope with `--tree` or the dedicated
  TUI action.
- The confirmation text must say how many processes will be targeted.
- The confirmation text must show the root PID and a bounded child preview.
- The normal `--yes` flag must not bypass protected-process confirmation.
- If the **root** is protected, the existing protected typed confirmation
  applies (PID or process name), then tree rules apply on top.
- If any **descendant** is protected, refuse the whole tree in v1.
- If the tree contains PID `0`, PID `1`, Kickoutchi's own PID, or another
  unsafe target, refuse the whole tree.
- If the tree cannot be fully enumerated within the caps, refuse instead of
  killing a partial tree. The pre-flight count runs **before any signal is
  sent**, so a cap refusal has zero side effects.
- Revalidate the root process (PID, name when known, start marker, confirmed
  ports) immediately before the freeze phase, using the existing rules.
- Collect the tree fresh at execution time; the confirmation preview is
  informational only. Do not rely on the stale details-panel child snapshot.
- Freeze before enumerating for kill: a stopped process cannot fork, and
  `/proc` child listings are only guaranteed complete for stopped children.
  Freezing is the correctness mechanism for **both** modes, not a force-only
  escalation.
- Signal ordering per node is mode-specific and mandatory:
  - Terminate: `SIGSTOP → verify → SIGTERM → SIGCONT`. A stopped process does
    not handle `SIGTERM` while stopped; the signal stays pending until
    `SIGCONT`. Skipping the CONT leaves a swamp of frozen processes with
    pending signals.
  - Force: `SIGSTOP → verify → SIGKILL`. `SIGKILL` terminates a stopped
    process directly; no CONT is needed.
- **Every abort path after freezing must `SIGCONT` everything already
  frozen** — cancelled confirmation, failed verification, cap overflow
  discovered mid-sweep, permission error on any member. Kickoutchi must never
  exit leaving processes stopped.
- Prefer normal termination for `--tree`; `SIGKILL` only for `--force --tree`.

## Architecture Fit

Current relevant files:

- `src/cli.rs` owns `kill` flags, confirmation, CLI exit codes, and pre-kill
  revalidation.
- `src/app.rs` owns TUI kill requests, confirmation modal state, background
  workers, and post-kill refresh.
- `src/process.rs` owns termination safety policy, target identity,
  confirmation requirements, PID guardrails, and signal delivery.
- `src/platform/linux.rs`, `src/platform/macos.rs`, and `src/platform/windows.rs`
  own OS-specific process collection and child snapshots.
- `src/model.rs` already has `ProcessContext` and `ChildProcessSnapshot` for
  selected-process children.

Add the shared concept in `src/process.rs`:

```rust
pub(crate) enum KillScope {
    Process,
    Tree,
}
```

Keep `KillMode` as the signal strength and `KillScope` as the target breadth.
This avoids mixing two separate choices: how hard to hit and how much of the
swamp to hit.

Add a tree plan type in `src/process.rs` or a small new module (`tree.rs`) if
the file gets too large:

```rust
pub(crate) struct ProcessTreeTarget {
    pub(crate) root: KillTarget,
    pub(crate) processes: Vec<ProcessTreeNode>,
    pub(crate) truncated: bool,
}

pub(crate) struct ProcessTreeNode {
    pub(crate) pid: u32,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) process_name: Option<String>,
    pub(crate) protected: bool,
    pub(crate) system_process: bool,
    pub(crate) start_time_marker: Option<u64>,
}
```

Required small refactor: the system-process classification currently lives on
`PortEntry` (`is_system_process`). Tree nodes are not port entries, so extract
the name/PID/parent-PID logic into a free function both can call. Protection
matching needs no refactor: `protection::is_protected_process_name` already
takes a platform and a name directly.

The tree plan is a kill-time artifact. It must not be part of `list --json`,
because JSON output is a stable socket-table contract (and `PortEntry.child_pids`
stays the reserved, empty field it is today).

## The Freeze-First Algorithm (shared Linux/macOS shape)

This is the core correction for the Dax situation. Order matters; every phase
exists to close a specific race.

1. **Confirm and revalidate the root.** Existing rules unchanged: PID, process
   name when known, start-time marker, confirmed ports. On Linux the root pidfd
   is opened before execution-time revalidation, exactly like the single-process
   kill path, and that same handle is reused for the root's stop, thaw, and
   final delivery.
2. **Pre-flight enumeration (no signals).** One bounded scan builds a
   parent→children map; BFS from the root counts the tree. If the count exceeds
   `MAX_TREE_PROCESSES`, refuse now — nothing has been touched, so refusal has
   zero side effects. This is what keeps a cap refusal from freezing half a
   bomb and then thawing it.
3. **Freeze sweep, root first.** `SIGSTOP` the **root before anything else** —
   a stopped root cannot fork, so the tree stops growing from the top. Then
   freeze its known children, re-scan, freeze newly discovered descendants, and
   repeat until a pass discovers nothing new (a fixed point). The tree can only
   grow from the shrinking frontier of not-yet-frozen descendants, so the sweep
   converges. Bound it twice: `MAX_TREE_PROCESSES` on total members and
   `MAX_FREEZE_PASSES` (e.g. 8) on sweep iterations. Exceeding either →
   `SIGCONT` everything frozen (reverse discovery order, root last, for
   determinism) → refuse. An `EPERM` on any `SIGSTOP` → CONT all → refuse with
   the permission-denied exit.
4. **Verify after stop.** For every frozen node, re-read parent PID and
   start-time marker. This post-stop verification is airtight: a stopped
   process cannot exec, and its PID cannot be recycled while the process
   exists, so the verified identity stays valid until we signal. Any mismatch →
   CONT all → refuse the whole tree. On Linux, each member is pinned with a
   pidfd before its first `SIGSTOP`; after stop-verify the already-held handle
   is reused for thaw and final delivery, making delivery reuse-proof end to
   end. On macOS there is no pidfd, but the stop-verify gate carries the same
   guarantee for descendants; only the root keeps the marker-recheck window
   accepted by the existing single-kill path.
5. **Policy check.** Unsafe PIDs (0, 1, self, and PID 4 on a future Windows) or
   any protected descendant → CONT all → refuse (protected refusal uses exit
   `6` semantics). Zombie members need no special casing: signals to a zombie
   are accepted and discarded by the kernel, so stopping and signalling them is
   a harmless no-op, and they are reaped when their parent dies.
6. **Signal phase, leaves first, root last.** Per node, apply the mode-specific
   ordering from the Safety Contract (`SIGTERM` then `SIGCONT` for Terminate;
   `SIGKILL` alone for Force). Leaves-first means a parent that respawns
   children on child-exit is still frozen when its children die, and by the
   time it is continued it is receiving its own termination.
7. **Report honestly.** Per-node outcomes; never claim success if any node
   failed; run the existing best-effort post-kill port refresh.

## Linux Implementation

Linux shipped in `1.0.0`.

Enumeration primitive: **reuse the existing full `/proc` scan** — the
`collect_child_processes_from` pattern already reads `PPid` from each
`/proc/<pid>/status` through the bounded reader. One pass builds the entire
parent→children map, it has no kernel-config dependency, and it reuses the
existing temp-proc-root test harness. `/proc/<pid>/task/<tid>/children` is a
possible later optimization, but it requires walking every thread directory of
every node, depends on `CONFIG_PROC_CHILDREN`, and per `proc(5)` is only
complete when children are stopped — the full scan is simpler and no less
correct.

Walk shape:

- Start from the confirmed root PID; keep `to_visit` and `nodes` vectors
  (iterative, never recursive).
- Cap the tree with `MAX_TREE_PROCESSES = 256` and the sweep with
  `MAX_FREEZE_PASSES`.
- Exclude and refuse on PID `0`, PID `1`, and Kickoutchi's own PID.
- Read process name, parent PID, and start-time marker
  (`parse_process_start_time_ticks` already exists) for every node.
- Mark protected names via `protection::is_protected_process_name` and system
  processes via the extracted classifier.

Signal delivery follows the freeze-first algorithm above. The root keeps its
pidfd path, and descendants get pidfds opened before their first `SIGSTOP`; the
same handles are reused for thaw and final delivery.

## macOS Implementation

macOS shipped in `1.0.0` alongside Linux.

Enumeration primitive: **reuse the existing all-PID scan** — `process_ids()`
plus `pbi_ppid` from `read_process_bsdinfo`, exactly like the existing
`collect_child_processes`. The `libc` crate does bind `proc_listchildpids`
(verified against libc 0.2.17x/0.2.18x), so a direct child listing is available
as a later optimization, but the full scan keeps one shape across both
platforms and reuses tested code.

Rules:

- Same `MAX_TREE_PROCESSES` and `MAX_FREEZE_PASSES` caps.
- Start markers come from `pbi_start_tvsec`/`pbi_start_tvusec` (the existing
  `process_start_time_marker_from_bsd_info`).
- Same freeze-first algorithm: SIGSTOP root first, fixed-point sweep, verify
  after stop, leaves-first signals, TERM-then-CONT ordering, CONT-on-abort.
- The stop-verify gate is what substitutes for pidfd on descendants: once
  stopped, a PID cannot be recycled, so verified identity holds until the
  signal lands.
- Refuse on partial enumeration or identity drift, as on Linux.

Do not attempt Bun's private macOS `p_uniqueid` tracking. It is too much
platform-specific surface for a user-driven kill command and the stop-verify
gate already closes the race it would address.

## Windows: The Combined `1.1.0` Phase, and the Design That Gets It There

Windows scoped cleanup ships as one combined `1.1.0` after the `1.0.0`
Linux/macOS release: CLI `--tree` and read-only `inspect` together, on the
job-containment design below. It was deferred out of `1.0.0` for verification
reasons — the tree-kill work repeatedly showed that live QA catches what tests
do not, and the hardest-to-verify platform must not gate the release of the two
already-verified ones. That deferral now has an end date: a real Windows machine
is available for the interactive QA this phase needs, so `1.1.0` proceeds with
the same "live QA before release" bar the Unix phase held itself to.

Scope of the combined `1.1.0`:

- **CLI `--tree`** — the job-containment tree kill designed below.
- **`inspect`** — read-only, and the cheapest half to port: it needs the same
  process snapshot (parent PID + creation-time marker under the sanity rule) but
  sends no signals, so it validates that shared enumeration foundation in a
  zero-risk context before any kill rides on top of it. The one adjustment:
  Windows has no POSIX process groups, so the report drops the "process group"
  section (or replaces it with Job Object membership when present) rather than
  inventing a group that does not exist.
- **`--group` stays Unix-only.** Process groups are a POSIX concept; the honest
  Windows analog *is* the Job Object, which tree kill already uses. Windows gets
  `--tree`, not `--group`.
- **TUI `t`/`T` on Windows** is an open sub-decision, not a commitment. Follow
  the Unix precedent — `--group` shipped CLI-first — and prefer CLI `--tree`
  first to bound the QA surface (the TUI adds a background worker, modal, and
  Caps Lock handling to verify). It can follow in a later release if the CLI
  path proves out.

Why the Unix design does not transfer directly:

- **No freeze primitive.** The Unix safety story rests on `SIGSTOP`: frozen
  processes cannot fork (so enumeration provably completes) and a stopped PID
  cannot be recycled (so post-stop identity verification is sound). Windows
  has no supported equivalent: `SuspendThread` is per-thread and racy against
  thread creation, and `NtSuspendProcess` is undocumented ntdll surface that a
  safety-critical kill path must not stand on — even though tools like Process
  Explorer use it, "stable for twenty years" is not "supported".
- **No graceful signal.** `TerminateProcess` and `TerminateJobObject` are
  immediate; there is no `SIGTERM` tier (console control events and `WM_CLOSE`
  apply only narrowly). The Terminate-vs-Force distinction collapses, as the
  single-kill path already documents.
- **Dangling parent PIDs.** Windows records the raw parent PID at creation and
  never updates it. When a parent dies and its PID is recycled, the child's
  recorded PPID points at an unrelated process. Naive PPID walks build wrong
  trees (`taskkill /T` walks them anyway; this design must not).

What Windows has instead — the two primitives the design stands on:

- **An open process handle pins the PID.** Windows does not recycle a PID
  while any handle to its process object exists. Open the handle first, then
  read the creation time through that same handle: verification and pinning
  are inherently ordered, which is the same reuse-proof delivery guarantee
  pidfd gives Linux — reached even more directly.
- **Job Objects kill atomically and contain normal future children.** A job
  cannot retroactively swallow an already-running tree (existing descendants
  stay outside it), but after a process is assigned, normal `CreateProcess`
  children inherit the job, and `TerminateJobObject` kills the current job
  membership simultaneously. This is strong, but not absolute: assignment can
  fail for processes already in incompatible jobs, nested-job/breakaway policy
  affects inheritance, and some creation paths (for example WMI
  `Win32_Process.Create`) do not associate children with the parent's job.
  Bun uses jobs from birth; this design uses them by assignment, so the copy and
  reports must call it containment, never a freeze-equivalent guarantee.

The design — containment instead of freezing. Unix *prevents* tree growth
(frozen processes cannot fork); Windows tries to *contain* it:

1. Resolve, confirm, and revalidate the root exactly as the Unix paths do:
   open the handle with `PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
   | PROCESS_SYNCHRONIZE | PROCESS_SET_QUOTA`, verify the creation-time marker
   through that same handle, and refuse unsafe/protected roots before any job
   is created.
2. Run a side-effect-free preflight snapshot before touching Job Objects:
   snapshot the process table, accept parent edges only under the creation-time
   sanity rule (a child's creation time must be later than its recorded
   parent's, or the edge is discarded as dangling), open and verify handles for
   every candidate member, and apply the same cap, unsafe-PID, protected
   descendant, and partial-metadata gates as Unix. This catches the obvious
   refusal cases while the operation can still promise no side effects.
3. The **commit boundary** is assigning the root to a Job Object. Job assignment
   is not reversible like `SIGSTOP`/`SIGCONT`: after the root is assigned,
   Kickoutchi has changed the process even if no process has been killed yet.
   Therefore all policy refusals that can be checked ahead of time must happen
   before this point, and post-commit failures must be reported as containment
   failures or partial termination, not as clean refusals.
4. Create a Job Object **without** `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` during
   planning/sweeping, then assign the root first. `kill-on-close` is too
   dangerous before the operation commits: an error path or dropped handle could
   terminate the root unintentionally. Use explicit `TerminateJobObject` only
   after the sweep reaches its commit-to-kill phase.
5. Sweep existing descendants to a fixed point, mirroring the Unix sweep shape
   and caps: resnapshot, accept only creation-time-sane parent edges, open and
   verify a handle per new member, and assign each assignable member to the job.
   `MAX_TREE_PROCESSES` and the pass limit apply unchanged, but after root
   assignment an overflow is no longer a zero-side-effect refusal. At that
   point the safest behavior is to stop discovering, terminate the job members
   already under containment, individually terminate any verified unassigned
   members that were part of the confirmed tree, and report the partial/overflow
   state honestly.
6. **`TerminateJobObject`: one atomic kill** of every assignable member in the
   job, including normal children spawned after their parent joined the job.
   This removes the Unix leaves-first ordering window for job-contained members,
   but only for members that successfully joined the job and only for children
   that inherit the job. The report must not claim Unix parity.
7. Members that cannot be assigned (`AssignProcessToJobObject` fails for
   processes already inside nesting-incompatible jobs, containers, some
   sandboxes and services, or session/job-policy reasons) are not silently
   ignored. If they were verified members of the confirmed tree, fall back to
   individual `TerminateProcess` through their held handles and report the
   weaker Windows-only path per PID. If handle open or verification fails,
   report that member as not terminated.

Honest limits to state in the user-facing copy when this ships:

- Hard kill only; no graceful tier exists on Windows.
- Enumeration is observed-complete ("the sweep converged"), not
  provably-complete ("frozen, therefore closed"). Job containment narrows that
  gap for normal child creation, but the wording must say "converged" and
  "contained", never claim a freeze.
- Before the root is assigned to a job, refusals are clean and side-effect-free.
  After root assignment, clean refusal is no longer possible; failures become
  partial/containment reports.
- Elevation applies as today: handles to higher-privilege processes fail to
  open. Before the commit boundary this is a permission-denied refusal. After
  the commit boundary it is a per-member failure report, because the root may
  already be contained.
- A new child spawned after root assignment is part of the Windows blast radius
  if it inherits the job. The confirmation copy must say that Windows may kill
  newly spawned job-contained children even if they were not visible in the
  preview.
- WSL2 processes are invisible to native Windows enumeration: they run inside a
  lightweight VM, so the Windows process table shows only `vmmem`/relay hosts,
  not the individual Linux processes. Windows `--tree`/`inspect` cannot see or
  reach them. State this plainly, and point WSL2 users at the Linux build inside
  WSL2, which handles those trees natively.

Architecture: a separate Windows execution path implementing the same
`TreeKillOutcome` contract — deliberately *not* a `TreeProcessOps`
implementation. The trait is shaped around freeze/verify/deliver; the job
design is assign/converge/terminate-atomically, and contorting one into the
other would obscure both. The confirmation flow, policy layer (protected
names, unsafe PIDs, `SystemProcessCheck`), banner and modal copy, and outcome
mapping are already platform-agnostic and are reused as-is.

Verification bar for the Windows phase:

- Unit tests for the planner (parent-map building under the creation-time
  sanity rule, side-effect-free preflight refusals, explicit commit boundary,
  sweep convergence, post-commit cap/overflow reporting, and job-assignment
  fallback) through injected seams, exactly as on Unix.
- Unit tests for existing-job and job-policy edge cases: root already in a
  compatible nested job, root/descendant in an incompatible job, assignment
  denied after handle verification, normal child captured by the job, and a
  breakaway/non-inheriting child that escapes containment and is reported.
- Windows CI contract tests mirroring the Linux/macOS tree tests; the helper
  ready-file pattern is already cross-platform. Add Windows helper cases for a
  runaway normal `CreateProcess` spawner after root assignment and an
  incompatible-job descendant that forces the individual-handle fallback.
- Manual QA on the real Windows machine — now available, so run it as a live
  loop during development, not only as a final gate. Cover the case that is the
  *common* dev setup, not an exotic edge: a dev server started from an editor or
  terminal that already manages its child tree with a Job Object (e.g. the
  VS Code integrated terminal, Windows Terminal). That is exactly the
  already-in-a-job / nested-assignment / individual-handle-fallback path.
  Test both `kick` launched from the *same* terminal (its own PID is inside that
  job — watch the self-PID guard) and from a *separate* standalone terminal.
- Open question to settle during the phase, not before: whether
  `NtSuspendProcess` is acceptable as *optional* best-effort hardening on top
  of the job design. Default answer is no (undocumented API in a kill path);
  the job design must be safe without it.

Until `1.1.0` ships, shipped Windows behavior stays exactly as it is in `1.0.0`:

- Normal process kill works exactly as before.
- The `--tree` and `--group` flags and the `inspect` subcommand do not exist on
  Windows builds: clap rejects them as unknown arguments (exit `2`, the existing
  usage-error code), pinned by Windows-only parse tests, and `--help` stays
  honest per platform for free — no runtime "unsupported" branch, no new exit
  code, no stale help text.
- The TUI does not bind `t`/`T` and does not advertise them in the header or
  help modal.

At `1.1.0`, `--tree` and `inspect` become available on Windows (the parse tests
that assert their exit `2` flip to assert acceptance). `--group` stays a clap
usage error (exit `2`) permanently — it is Unix-only by design, so its
Windows-only parse test is kept, not flipped.

## CLI Plan

Add to `KillArgs` in `src/cli.rs` (Unix builds only, per the cfg-gate above):

```rust
#[arg(long)]
pub(crate) tree: bool,
```

Derive scope near the existing mode selection:

```rust
let scope = if args.tree {
    KillScope::Tree
} else {
    KillScope::Process
};
```

Update the kill banner:

- Show `Scope: process` or `Scope: tree`.
- For tree scope, show the total process count and a bounded preview
  (first N nodes, sanitized names).
- Keep existing warnings for protected, system, owner UID, partial metadata,
  and child processes.

Update confirmation:

- `--tree` without `--yes`: require typing `tree` (Terminate) or `force`
  (Force). A new `ConfirmationRequirement` variant follows the existing enum
  pattern.
- `--tree --yes`: allowed only if there are no protected/system/partial/
  truncated warnings anywhere in the tree; otherwise fall back to the typed
  prompt. `--yes` opts out of being asked, never out of being told — the
  banner and warnings still print, as on the existing `--yes` path.
- A protected **root** still requires the protected PID-or-name confirmation.
  A protected **descendant** refuses the whole tree (v1 decision).

Exit behavior reuses existing codes; nothing new is added:

- Permission problems (including `EPERM` on any freeze) use `PermissionDenied`
  (4).
- Protected refusal uses `ProtectedNeedsConfirmation` (6).
- Cap overflow and identity-drift refusals use `Failure` (1) with messages
  that name the cap or the drifted node.
- Windows `--tree` is a clap usage error (2) via the cfg-gate.

## Implemented TUI Tree Mode

The TUI tree path shipped in `1.0.0` on Linux/macOS.

- One dedicated tree action pair in `src/input.rs`: `t` terminates the selected
  tree and `T` force-kills it, mirroring the `x`/`X` Shift and Caps Lock
  handling. Tree mode comes from an explicit action, never from the details
  panel being open.
- Tree confirmation state lives in `src/app.rs`, alongside the existing
  single-process `KillConfirmation`.
- **Preview collection runs on a background worker**, the same pattern as the
  details/Docker context worker: the full-`/proc` scan must not block the
  render/input loop. The modal opens immediately in a loading state; if the
  enumeration then fails a pre-flight gate (cap, unsafe PID, protected
  descendant), the modal closes and the refusal lands as a kill status line.
- The confirmation modal (`src/ui/confirm.rs`) shows: root identity, total
  tree size, a bounded node preview, the scope, and the typed-word prompt
  (`tree` or `force`). Auto-refresh already pauses while a confirm modal is
  open; keep that.
- **Execution re-runs the whole freeze pipeline fresh.** The preview is
  informational. Policy for drift between preview and execution: the root must
  match exactly (existing revalidation rules); tree *membership* may differ —
  children churn is normal — but the fresh tree must still pass every gate
  (cap, unsafe PIDs, no protected descendants), or the whole operation
  refuses. Report the fresh count in the status line so drift is visible.
- `src/ui/help.rs` and the header hint advertise `t/T` only on Linux/macOS
  builds. Windows builds do not bind or show tree keys.
- Normal kill confirmation stays byte-for-byte unchanged.

## Implemented `--group` Mode

`--group` targets a process group rather than a parent-child tree. This is also
the honest answer to trees that exceed the cap (the true fork-bomb case),
because process-group membership does not require walking a racing tree.

Use case:

- Shells, package runners, and dev tools often keep related processes in the
  same process group.
- A child may survive even if it is no longer a direct descendant of the port
  owner (double-fork daemons, reparented orphans).

Risks:

- Process groups can include unrelated commands launched from the same shell.
- PID `0` has special meaning for `kill`, so the existing unsafe-PID guardrail
  must remain strict.
- Process-group membership can be surprising when terminals, shells, and job
  control are involved.

Implementation:

- Linux/macOS only.
- Display the process group ID and every visible member before confirmation.
- Cap group members with `MAX_GROUP_PROCESSES` and refuse on truncation.
- Require strong typed confirmation even with `--yes` unless the group is tiny
  and all members are unprotected user processes; the fresh execution-time scan
  must still pass the same all-clear gate if the prompt was skipped.
- Never implement this by calling `kill(0, signal)` or `kill(-pgid, signal)`
  directly from user input. Enumerate, verify, and signal known members.
- Queue every group member's terminating signal before continuing any stopped
  member, so parent-like group members cannot wake up and spawn survivors while
  children are still frozen.

## No Automatic `--family` Kill

Read-only family/group inspection shipped as `kick inspect`. Automatic family
kill remains deliberately out of scope. This is for supervisor or AI-agent cases
where killing the port owner is not enough because a parent process respawns it.

Use case:

- Agent starts shell.
- Shell starts package runner.
- Package runner starts dev server.
- Dev server owns port.
- Killing only the dev server causes the runner or agent to bring it back.

Risks:

- Ancestors may include the user's shell, terminal, editor, or agent host.
- Killing upward is much more dangerous than killing downward.
- The root cause may be a supervisor, not a normal process family.

Implemented stance:

- `kick inspect --port <PORT>` and `kick inspect --pid <PID>` show ancestors,
  siblings, descendants, process group, command lines, and ports.
- The report suggests `kick kill --pid <root> --tree` and only suggests
  `--group` when group scope would catch members outside the descendant tree.
- The user chooses an explicit root PID from the preview.
- Tree kill from that selected root is the kill action. There is no broad
  automatic family kill.

Recommendation: keep avoiding automatic `--family` kill. Prefer "inspect family,
choose root, then tree-kill that root". Donkey can yell about the family, but
the ogre should still point at exactly one door before kicking it in.

## Security Review Checklist

- Confirm every kill path starts from a user-confirmed root PID.
- Confirm root target revalidation still checks PID, process name when known,
  start marker, and confirmed ports.
- Confirm the freeze order is root-first and enumeration reaches a fixed point
  before any termination signal is sent.
- Confirm the pre-flight cap check runs before any signal, so cap refusals have
  zero side effects.
- Confirm identity verification happens **after** `SIGSTOP`, where PID reuse is
  impossible, and that Linux descendants already hold pidfds from before their
  first `SIGSTOP`.
- Confirm the Terminate path sends `SIGTERM` before `SIGCONT`, and that Force
  sends `SIGKILL` with no CONT.
- Confirm every abort path after freezing continues every frozen process — no
  exit leaves anything in state `T`.
- Confirm recursive modes never target PID `0`, PID `1`, Kickoutchi, or
  protected descendants; a protected root requires the typed confirmation.
- Confirm truncated or partial trees refuse by default.
- Confirm no shell commands are constructed or executed for killing.
- Confirm all process enumeration reads use the existing bounded readers.
- Confirm errors never claim success when only part of a tree was signaled.

## Test Plan

Unit tests (temp proc-root harness, as in `linux.rs` today):

- Tree enumeration returns root plus descendants in deterministic order.
- Zero-child tree behaves like process scope but still reports tree scope.
- Pre-flight cap overflow refuses with no signals recorded (injected signal
  seam observes zero calls).
- Mid-sweep cap or pass-limit overflow records CONT for every previously
  stopped PID before refusing.
- Unsafe PIDs inside a tree refuse the whole operation.
- Protected descendant refuses the whole tree; protected root routes to the
  protected confirmation requirement.
- Verification-after-stop rejects a changed child parent PID or start marker,
  and records CONT for everything frozen.
- Revalidation rejects a changed root start marker.
- Signal planner emits leaves-first order, root last.
- Terminate mode emits `STOP → TERM → CONT` per node in that order; Force
  emits `STOP → KILL` with no CONT. (Pin the ordering — it is a correctness
  rule, not a style choice.)

CLI contract tests:

- `kick kill --port <port> --tree` shows tree scope, the count, and requires
  the typed word.
- `kick kill --port <port> --tree --yes` does not bypass protected tree checks.
- `kick kill --port <port> --tree --force` uses force wording and force signal.
- On Windows builds, `--tree` fails at argument parsing with exit `2`.

Integration tests on Linux (extend the existing helper-listener pattern in
`tests/cli_contract.rs`):

- Parent owns the port and has one child; tree kill removes both.
- Child owns the port; tree kill from `--pid parent` removes both.
- Root exits before confirmation completes; no descendant signal is sent.
- A child forks a grandchild after the preview but before execution; the fresh
  execution-time collection still catches and kills it (the freeze-sweep test).
- A stopped (`SIGSTOP`ped beforehand) member still dies under Terminate mode —
  pins the TERM-before-CONT rule end to end.
- An aborted run (declined confirmation after preview) leaves no helper in
  state `T` (read `/proc/<pid>/stat` state field).

Flakiness controls:

- Use helper binaries and pipes/ready-files, not sleeps, to coordinate process
  readiness (the ready-file pattern already exists in `cli_contract.rs`).
- Allocate ports through the OS (`bind :0`) instead of hardcoding.
- Helper trees must be bounded and self-terminating (children `sleep` with a
  deadline) so a failed test cannot leave a runaway tree behind.
- Always clean up helper processes in test teardown (`ChildGuard` pattern),
  including `SIGCONT` before kill in guards, in case a test dies mid-freeze.
- Keep tests serial only when they share process-tree assumptions.

## QA Plan

Manual QA on Linux first:

```sh
kick kill --port 3000
kick kill --port 3000 --tree
kick kill --port 3000 --tree --force
kick kill --pid <root> --tree
kick list --json
```

Observe:

- Normal kill still targets only one PID.
- Tree kill prints the root, scope, and process count before confirmation.
- Refusing confirmation leaves every process alive **and running** (nothing
  left in state `T` — check with `ps -o stat`).
- Successful tree kill removes the confirmed ports.
- A respawning tree under the cap actually dies (run a small spawner script
  that forks workers in a loop; tree kill must converge, not whack-a-mole).
- A tree over the cap is refused cleanly with the cap named and nothing frozen
  afterward.
- If a survivor respawns the port, Kickoutchi reports that the port is still
  visible instead of claiming the swamp is clean.

Manual QA on macOS after implementation:

- Repeat every Linux flow with native macOS process trees.
- Verify PID-reuse checks with fast-exiting helper processes.
- Verify permission-denied cases (`sudo`-owned member) produce a safe refusal
  with everything continued.

Manual QA on Windows:

- Verify `--tree` is rejected at argument parsing (exit 2) and does not appear
  in `--help`.
- Verify normal `kick kill` still works as before.

## Rollout

Completed for `1.0.0`:

- Shared tree/group planning, system-process classification, and injected signal
  seams.
- Linux CLI `--tree`, freeze-first execution, pidfd-backed delivery, CLI
  contract tests, and real-process QA.
- macOS tree/group planning and execution on the existing `pbi_ppid`/
  `pbi_pgid` scan, with Darwin cross-target checks.
- TUI `t`/`T` tree action, background preview worker, confirmation UI, help
  modal, and platform-gated header hints.
- Read-only family/group inspection through `kick inspect`.
- CLI `--group` kill, including full-member confirmation and the queued
  TERM-before-CONT ordering fix.
- Release metadata, docs, package verification, and `1.0.0` changelog.

Next — combined `1.1.0` (Windows CLI `--tree` + `inspect`, delivered together):

- Windows `inspect` first as the shared read-only foundation: the process
  snapshot (parent PID + creation-time marker under the sanity rule) that tree
  kill also depends on, validated with no signals and minus the POSIX
  process-group section.
- Windows `--tree`, built on the job-containment design in the Windows section:
  handles pin PIDs for reuse-proof delivery, a Job Object without kill-on-close
  marks the irreversible commit boundary, and explicit `TerminateJobObject`
  kills contained members atomically.
- `--group` stays Unix-only; no Windows `--group` in `1.1.0` or later.
- Windows docs/copy must stay honest: containment and convergence, not Unix
  freeze parity; hard-kill-only; and WSL2 processes are out of reach.
- Manual Windows QA on the available machine is required before shipping — run
  as a live loop, with the editor/terminal Job Object case covered explicitly.
- `1.1.0` is a minor bump: making previously-rejected flags valid on Windows is
  a backwards-compatible feature addition, and the Unix paths are unchanged.

## Resolved Decisions

Previously open questions, now decided:

1. `--tree` does **not** require `--force`. Normal tree mode sends `SIGTERM`
   leaves-first; escalation is `--force --tree` with `SIGKILL`. Punishing the
   graceful path would push users straight to force.
2. A protected **descendant** refuses the whole tree in v1. Typing one
   protected name must not authorize killing N processes around it. A
   protected **root** uses the existing typed protected confirmation. Revisit
   after real-world use.
3. Stop-verify (the freeze) applies to **both** modes, always. It is the
   mechanism that makes enumeration complete and identity checks sound — not a
   force-only escalation. The mode only changes the final signal and the CONT
   rule.
4. The TUI collects and shows the **full bounded tree** before confirmation,
   on a background worker. Direct-children-only would understate the blast
   radius. Execution always re-collects fresh; root identity must match
   exactly, membership may drift but must re-pass every gate.

## Recommendation

Treat Linux/macOS `1.0.0` scoped cleanup as complete and maintain it with the
same safety contract: opt-in scope, bounded scans, count before signals, freeze
before final enumeration, verify while stopped, and thaw on every refusal. The
next product/engineering focus is Windows scoped cleanup, shipped as one
combined `1.1.0` (CLI `--tree` + `inspect`) on its own job-containment path,
with real Windows QA before release.
