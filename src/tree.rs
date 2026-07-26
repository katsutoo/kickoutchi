//! Process-tree planning plus the Unix freeze-first execution pipeline.
//!
//! Single-process kill (see `process.rs`) is precise on purpose: it signals
//! exactly one confirmed PID. Tree kill is the big ogre button — it terminates a
//! confirmed root together with its descendants — and its whole design exists to
//! win one specific race: a target that keeps spawning children faster than you
//! can kill them.
//!
//! Group kill shares the same freeze-first pipeline but derives membership from
//! the POSIX process group instead of parent links. It exists for the two cases
//! tree scope honestly cannot cover: survivors that reparented away from the
//! tree (double-fork daemons, orphaned workers) and runaway spawners whose tree
//! outgrows the tree cap. It is deliberately never implemented as
//! `kill(-pgid)`: every member is enumerated, frozen, identity-verified, and
//! signalled individually, so the same refusal gates apply to every PID.
//!
//! On Unix, the trick is to freeze before you count. A process observed stopped
//! cannot `fork` unless another actor continues it, so the tree normally stops
//! growing from the root while a bounded re-scan sweep reaches descendants.
//! Identity is re-checked after each observed stop; Linux pins delivery with a
//! pidfd and macOS re-checks start markers at each raw-PID boundary. Any refusal
//! after freezing thaws only processes Kickoutchi transitioned to stopped, so an
//! externally stopped process is not resumed as refusal cleanup. Concurrent
//! external `SIGSTOP`/`SIGCONT` can still race those observations; scoped kill is
//! bounded best-effort convergence, not an atomic kernel transaction.
//!
//! This module is the pure orchestration. All real process I/O — enumerating
//! `/proc`, sending signals — is injected through [`TreeProcessOps`], so the
//! whole pipeline is exercised in tests with a fake that scripts snapshots and
//! records the exact order of stop/continue/signal calls.

use std::collections::{HashMap, HashSet};

use crate::model::{Platform, SystemProcessCheck};
use crate::observation::ProcessStartMarker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process::current_user_id;
use crate::process::{KillMode, UnsafePidReason, unsafe_pid_reason};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process::{KillTarget, UNIX_STOP_ACKNOWLEDGEMENT_MAX};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process_evidence::{
    ExpectedProcessEvidence, FreshProcessEvidence, ProcessEvidenceError, ProcessEvidenceScope,
};
use crate::protection::is_protected_process_name;

/// Hard cap on the number of processes a single tree kill will touch.
///
/// A real dev-server or agent tree is a handful to a few dozen processes. This
/// ceiling is generous for that and still bounds the work per kill. A tree that
/// exceeds it is refused, not partially killed: partial kills of a runaway
/// spawner report false progress while the survivors regrow.
pub(crate) const MAX_TREE_PROCESSES: usize = 256;
pub(crate) const PROCESS_TREE_INDEX_MAX: usize = crate::observation::CANDIDATE_PROCESS_IDS_MAX;

/// Hard cap on the number of processes a single group kill will touch.
///
/// Higher than the tree cap because group scope is the designated tool for
/// runaway spawners whose tree outgrows [`MAX_TREE_PROCESSES`]. Still a hard
/// bound: past it the kill is refused, never partially executed. The value
/// also respects a resource budget — on Linux every member holds one pidfd
/// during delivery, and 512 stays comfortably under the common 1024
/// soft file-descriptor limit.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const MAX_GROUP_PROCESSES: usize = 512;

/// Cap on freeze-sweep passes. Every pass drains one snapshot completely, so a
/// static tree of any depth freezes in a single pass; a process cannot fork on
/// its own while it remains stopped, so passes only repeat while genuinely new
/// processes appear between snapshots. Exhausting the cap without a clean pass
/// means the member set kept churning and could not be enumerated completely,
/// so the kill is refused rather than run against a set we cannot vouch for.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_FREEZE_PASSES: usize = 8;

/// Ceiling on group size for a `--yes` prompt skip. A tiny, all-clear group is
/// the only group kill allowed to proceed without the typed word, and the same
/// ceiling is re-applied to the final frozen set: a group that grows past it
/// mid-freeze no longer matches what `--yes` was allowed to skip for.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const GROUP_YES_SKIP_MAX_PROCESSES: usize = 8;

/// One raw process as read from a single snapshot of the process table.
///
/// The platform layer fills these; the pipeline derives every tree relationship
/// from `parent_pid` and every identity check from `start_time_marker`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeProcessInfo {
    pub(crate) pid: u32,
    /// Parent edge accepted for tree walking. On Windows this is set only after
    /// the creation-time sanity rule proves the recorded parent PID has not gone
    /// dangling or been recycled.
    pub(crate) parent_pid: Option<u32>,
    /// A recorded parent PID that could not be sanity-checked because required
    /// creation-time metadata was missing. Tree rendering ignores this edge, but
    /// Windows tree kill treats it as fail-closed partial metadata if the edge
    /// could belong under the confirmed root.
    pub(crate) unverified_parent_pid: Option<u32>,
    pub(crate) parent_process_name: Option<String>,
    pub(crate) process_name: Option<String>,
    pub(crate) start_time_marker: Option<ProcessStartMarker>,
    /// Effective owner UID when readable. Drives the ownership warning in kill
    /// banners; deliberately not part of identity verification, which stands on
    /// the start marker and the scope relation.
    pub(crate) owner_uid: Option<u32>,
    /// Process group ID. `None` means the kernel domain (pgid `0`), which is
    /// never a targetable group. Group kill derives its membership from this
    /// field, so the platform snapshots read it as fail-closed as the start
    /// marker: a live process whose group cannot be read fails the whole scan,
    /// because a hole here would silently exclude a member from the kill.
    pub(crate) process_group: Option<u32>,
}

/// The result of asking the OS to deliver one signal to one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum TreeSignalResult {
    /// The signal was accepted by the kernel.
    Delivered,
    /// No such process — it exited before we signalled it.
    NotFound,
    /// Permission denied, or any other refusal we treat conservatively as one.
    Denied,
}

/// Result of stopping one member, including cleanup ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum TreeStopResult {
    /// Stopped state was observed. `transitioned` is false when it was already
    /// stopped before Kickoutchi submitted `SIGSTOP`.
    Stopped { transitioned: bool },
    /// The process exited before stopped state could be established.
    NotFound,
    /// The stop failed. A successful submission can still require cleanup when
    /// the bounded stopped-state observation subsequently fails.
    Failed {
        cleanup_required: bool,
        rollback_start_time_marker: Option<ProcessStartMarker>,
        error: TreeStopError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum TreeStopError {
    PermissionDenied,
    ObservationFailed(String),
}

/// What portion of the process table a platform snapshot should prove.
///
/// Linux already reads a complete `/proc` table cheaply. macOS uses this during
/// execution to avoid unrelated `EPERM` rows from hiding real scoped members:
/// tree scope can walk descendants directly, and group scope can prove denied
/// rows are outside the confirmed process group before skipping them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum TreeSnapshotScope {
    #[cfg(target_os = "macos")]
    Full,
    Tree {
        root_pid: u32,
    },
    Group {
        root_pid: u32,
        pgid: u32,
    },
}

/// The injected process I/O the pipeline drives.
///
/// A trait rather than loose closures because there are four related operations
/// and a fake needs to implement all of them coherently (scripted snapshots plus
/// a recorded call log). The real Linux implementation lives in
/// `platform/linux.rs`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) trait TreeProcessOps {
    /// Narrow subsequent snapshots to the scope currently being executed.
    ///
    /// The default keeps platforms and tests with complete snapshots unchanged.
    fn set_snapshot_scope(&mut self, _scope: TreeSnapshotScope) {}

    /// One fresh read of the whole process table.
    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String>;
    /// Pin the confirmed root before execution-time revalidation.
    ///
    /// Linux overrides this to open and retain the root pidfd before the final
    /// identity checks. macOS has no pidfd equivalent, so the default no-op keeps
    /// its existing stop-then-verify safety model.
    fn pin_root_for_revalidation(&mut self, _pid: u32) -> TreeSignalResult {
        TreeSignalResult::Delivered
    }
    /// `SIGSTOP` a process.
    fn stop(&mut self, pid: u32) -> TreeSignalResult;
    /// Stop and wait for observable stopped state, retaining whether cleanup may
    /// later send `SIGCONT`.
    ///
    /// Real Unix signal helpers publish the richer result while preserving the
    /// older signal-shaped `stop` boundary used by platform adapters. Test and
    /// preview implementations that do not publish one retain the historical
    /// assumption that a delivered fake stop made the transition.
    fn stop_checked(&mut self, pid: u32, deadline: std::time::Instant) -> TreeStopResult {
        if self.stop_acknowledgement_now() >= deadline {
            return TreeStopResult::Failed {
                cleanup_required: false,
                rollback_start_time_marker: None,
                error: TreeStopError::ObservationFailed(
                    "the operation-wide SIGSTOP acknowledgement deadline expired".to_owned(),
                ),
            };
        }
        let result = crate::process::with_tree_stop_deadline(deadline, || self.stop(pid));
        crate::process::take_tree_stop_result(pid).unwrap_or(match result {
            TreeSignalResult::Delivered => TreeStopResult::Stopped { transitioned: true },
            TreeSignalResult::NotFound => TreeStopResult::NotFound,
            TreeSignalResult::Denied => TreeStopResult::Failed {
                cleanup_required: false,
                rollback_start_time_marker: None,
                error: TreeStopError::PermissionDenied,
            },
        })
    }
    /// Clock used to bound stopped-state acknowledgement across this operation.
    /// Implementations normally use the monotonic system clock; deterministic
    /// fakes can override it without sleeping.
    fn stop_acknowledgement_now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
    /// Capture the identity that accepted `SIGSTOP`, for guarded rollback.
    ///
    /// Linux continuation is pinned by pidfd, so retaining the previously
    /// observed marker is sufficient there. macOS overrides this to read the
    /// identity immediately after the raw-PID stop succeeds.
    fn rollback_identity_after_stop(
        &mut self,
        _pid: u32,
        prior_marker: Option<ProcessStartMarker>,
    ) -> Option<ProcessStartMarker> {
        prior_marker
    }
    /// `SIGCONT` a process.
    ///
    /// `NotFound` leaves no stopped survivor — the process is gone, so there is
    /// nothing to resume and nothing to report. Only `Denied` is a cleanup
    /// failure: the process is still there and may still be stopped. Every
    /// caller classifies on `Denied` alone; see [`thaw_all`].
    fn cont(&mut self, pid: u32) -> TreeSignalResult;
    /// Retain the verified identity needed to make a raw-PID thaw safe.
    fn prepare_thaw(&mut self, _pid: u32, _marker: Option<ProcessStartMarker>) {}
    /// Prepare reuse-proof delivery for a stopped, verified process.
    ///
    /// `verified_start_marker` is the start marker the post-stop verification
    /// just proved. Linux ignores it (the pidfd held since the first stop is
    /// the reuse proof); macOS has no pidfd, so it records the marker and
    /// re-checks it immediately before every raw-PID signal to the member.
    fn prepare_delivery(
        &mut self,
        pid: u32,
        verified_start_marker: Option<ProcessStartMarker>,
    ) -> TreeSignalResult;
    /// Read identity and name again at the final delivery boundary.
    fn fresh_process_evidence(
        &mut self,
        pid: u32,
    ) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
        let snapshot = self
            .snapshot()
            .map_err(|_| ProcessEvidenceError::Missing { pid })?;
        let info = snapshot
            .iter()
            .find(|info| info.pid == pid)
            .ok_or(ProcessEvidenceError::Missing { pid })?;
        Ok(FreshProcessEvidence {
            pid,
            start_marker: info
                .start_time_marker
                .ok_or(ProcessEvidenceError::Missing { pid })?,
            name: info
                .process_name
                .clone()
                .ok_or(ProcessEvidenceError::NameMissing { pid })?,
        })
    }
    /// Deliver the terminating signal (`SIGTERM` for terminate, `SIGKILL` for
    /// force).
    fn deliver(&mut self, pid: u32, mode: KillMode) -> TreeSignalResult;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn pin_root_before_revalidation<Ops: TreeProcessOps>(
    root_pid: u32,
    ops: &mut Ops,
) -> Result<(), TreeKillOutcome> {
    match ops.pin_root_for_revalidation(root_pid) {
        TreeSignalResult::Delivered => Ok(()),
        TreeSignalResult::NotFound => Err(TreeKillOutcome::RootAlreadyExited),
        TreeSignalResult::Denied => Err(TreeKillOutcome::PermissionDenied { pid: root_pid }),
    }
}

/// One node in the preview tree shown before confirmation.
///
/// The preview is informational: it is built from a single un-frozen snapshot,
/// so a racing spawner can make it undercount. Execution re-enumerates under the
/// freeze and is the authority; this only drives the confirmation banner and the
/// pre-flight refusals that have zero side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessTreeNode {
    pub(crate) pid: u32,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) parent_process_name: Option<String>,
    pub(crate) process_name: Option<String>,
    pub(crate) owner_uid: Option<u32>,
    pub(crate) protected: bool,
    pub(crate) system_process: bool,
    pub(crate) depth: usize,
}

/// The previewed member set: the root at depth 0 plus the rest, and whether the
/// cap was hit while building it. Tree scope puts descendants at their real
/// depth; group scope puts every non-root member at depth 1 because membership
/// is flat. The final group signal step still queues all terminating signals
/// before continuing anyone, so parent-like members cannot wake before their
/// children have a pending termination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessTreeTarget {
    nodes: Vec<ProcessTreeNode>,
    truncated: bool,
    /// The member cap this preview was built under, carried so refusal
    /// messages always name the cap that actually applied (the tree and group
    /// caps differ).
    limit: usize,
}

/// Why a tree preview could not be built at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreePlanError {
    /// The root PID is not present in the snapshot — it exited already.
    RootMissing,
    SnapshotLimitExceeded {
        limit: usize,
    },
}

pub(crate) fn plan_error_outcome(error: TreePlanError) -> TreeKillOutcome {
    match error {
        TreePlanError::RootMissing => TreeKillOutcome::RootAlreadyExited,
        TreePlanError::SnapshotLimitExceeded { limit } => TreeKillOutcome::Truncated { limit },
    }
}

#[derive(Debug)]
pub(crate) struct ProcessTreeIndex<'a> {
    by_pid: HashMap<u32, &'a TreeProcessInfo>,
    children_by_parent: HashMap<u32, Vec<&'a TreeProcessInfo>>,
}

impl<'a> ProcessTreeIndex<'a> {
    pub(crate) fn new(
        snapshot: &'a [TreeProcessInfo],
        limit: usize,
    ) -> Result<Self, TreePlanError> {
        if snapshot.len() > limit {
            return Err(TreePlanError::SnapshotLimitExceeded { limit });
        }
        let mut by_pid = HashMap::with_capacity(snapshot.len());
        let mut children_by_parent: HashMap<u32, Vec<&TreeProcessInfo>> = HashMap::new();
        for info in snapshot {
            by_pid.entry(info.pid).or_insert(info);
            if let Some(parent_pid) = info.parent_pid {
                children_by_parent.entry(parent_pid).or_default().push(info);
            }
        }
        for children in children_by_parent.values_mut() {
            children.sort_by_key(|info| info.pid);
        }
        Ok(Self {
            by_pid,
            children_by_parent,
        })
    }

    pub(crate) fn process(&self, pid: u32) -> Option<&'a TreeProcessInfo> {
        self.by_pid.get(&pid).copied()
    }

    fn children(&self, pid: u32) -> &[&'a TreeProcessInfo] {
        self.children_by_parent.get(&pid).map_or(&[], Vec::as_slice)
    }
}

/// Why a group preview could not be built at all.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupPlanError {
    /// The root PID is not present in the snapshot — it exited already.
    RootMissing,
    /// The root has no targetable process group: its group could not be read,
    /// or it lives in the kernel's group `0`.
    GroupUnavailable,
}

impl ProcessTreeTarget {
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn root(&self) -> Option<&ProcessTreeNode> {
        self.nodes.iter().find(|node| node.depth == 0)
    }

    /// Protected descendants (never the root). v1 refuses the whole tree if any
    /// exist, so the caller only needs the first.
    pub(crate) fn protected_descendants(&self) -> impl Iterator<Item = &ProcessTreeNode> {
        self.nodes
            .iter()
            .filter(|node| node.depth > 0 && node.protected)
    }

    /// The first node whose PID is an unsafe target (0, 1, or Kickoutchi
    /// itself). The root is already blocked at resolution; this guards
    /// descendants such as Kickoutchi appearing inside its own target's tree.
    pub(crate) fn first_unsafe_node(&self) -> Option<&ProcessTreeNode> {
        self.nodes
            .iter()
            .find(|node| unsafe_pid_reason(node.pid).is_some())
    }

    pub(crate) fn has_system_process(&self) -> bool {
        self.nodes.iter().any(|node| node.system_process)
    }

    fn has_unreadable_name(&self) -> bool {
        self.nodes.iter().any(|node| node.process_name.is_none())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn has_owner_mismatch(&self) -> bool {
        let current_uid = current_user_id();
        self.nodes.iter().any(|node| {
            node.owner_uid
                .is_some_and(|owner_uid| owner_uid != current_uid)
        })
    }

    /// Whether the tree carries anything worth a stronger look before a `--yes`
    /// kill: system/service members, members owned by another uid, or members
    /// whose metadata we could not read.
    pub(crate) fn has_warnings(&self) -> bool {
        let base_warnings = self.has_system_process() || self.has_unreadable_name();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            base_warnings || self.has_owner_mismatch()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            base_warnings
        }
    }

    /// Nodes for the banner preview, capped, in display order (depth then PID).
    pub(crate) fn preview_nodes(&self, max: usize) -> &[ProcessTreeNode] {
        let end = max.min(self.nodes.len());
        &self.nodes[..end]
    }
}

/// The word a tree kill must have typed to proceed: the more dangerous mode
/// wants the more deliberate word. Shared by the CLI prompt and the TUI modal
/// so the two surfaces can never ask for different words.
pub(crate) fn tree_scope_word(mode: KillMode) -> &'static str {
    match mode {
        KillMode::Force => "force",
        KillMode::Terminate => "tree",
    }
}

/// The word a group kill must have typed to proceed. `force` stays the force
/// word across every scope — the word confirms deliberateness, the banner
/// names the scope.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn group_scope_word(mode: KillMode) -> &'static str {
    match mode {
        KillMode::Force => "force",
        KillMode::Terminate => "group",
    }
}

/// Whether typed confirmation input satisfies the scope word. Case-insensitive
/// so Caps Lock cannot trap the user, exactly like the single-kill `force` word.
pub(crate) fn word_confirmation_matches(input: &str, word: &str) -> bool {
    input.trim().eq_ignore_ascii_case(word)
}

/// Comma-separated PID list for denied-delivery reporting, shared by the CLI
/// and TUI outcome text.
pub(crate) fn format_pid_list(pids: &[u32]) -> String {
    pids.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The pre-flight gates every tree kill must pass before any signal is sent:
/// complete enumeration, no unsafe PIDs, no protected descendants. Shared by
/// the CLI and the TUI so a gate can never exist on one surface and not the
/// other. Zero side effects: this only inspects an already-built preview.
pub(crate) fn preflight_outcome(preview: &ProcessTreeTarget) -> Result<(), TreeKillOutcome> {
    if preview.truncated() {
        return Err(TreeKillOutcome::Truncated {
            limit: preview.limit,
        });
    }
    if let Some(node) = preview.first_unsafe_node() {
        return Err(TreeKillOutcome::UnsafePid {
            pid: node.pid,
            reason: unsafe_pid_reason(node.pid).expect("preview returned an unsafe node"),
        });
    }
    if let Some(node) = preview.protected_descendants().next() {
        return Err(TreeKillOutcome::ProtectedDescendant {
            pid: node.pid,
            name: node.process_name.clone(),
        });
    }
    Ok(())
}

/// The protected-root gate for a tree kill.
///
/// The confirmation stage is decided from whatever names were readable at the
/// time — but the port row and the process-table scan are different readers,
/// and `exec` swaps a process's name without changing its PID, parent, or start
/// marker. So a root can turn out protected only in a later scan. This gate
/// runs against the freshest preview: a protected root proceeds only when the
/// protected-root confirmation was actually completed. Both surfaces call it,
/// so neither can drift into trusting a stale protection verdict.
pub(crate) fn root_protection_outcome(
    preview: &ProcessTreeTarget,
    protected_confirmation_completed: bool,
) -> Result<(), TreeKillOutcome> {
    if protected_confirmation_completed {
        return Ok(());
    }
    if let Some(root) = preview.root()
        && root.protected
    {
        return Err(TreeKillOutcome::ProtectedRoot {
            pid: root.pid,
            name: root.process_name.clone(),
        });
    }
    Ok(())
}

/// Build the preview tree from a single snapshot.
///
/// Pure: no signals, no freezing. An iterative walk from the root over
/// `parent_pid` edges (traversal order does not matter — nodes are normalized
/// by the final depth-then-PID sort), enriching each node with the protection
/// and system/service policy. Stops adding nodes at `limit` and reports
/// truncation instead of erroring, so the caller can refuse a too-large tree
/// with zero side effects.
pub(crate) fn plan_process_tree(
    root_pid: u32,
    snapshot: &[TreeProcessInfo],
    protected_names: &[String],
    platform: Platform,
    limit: usize,
) -> Result<ProcessTreeTarget, TreePlanError> {
    let index = ProcessTreeIndex::new(snapshot, PROCESS_TREE_INDEX_MAX)?;
    plan_process_tree_with_index(root_pid, &index, protected_names, platform, limit)
}

pub(crate) fn plan_process_tree_with_index(
    root_pid: u32,
    index: &ProcessTreeIndex<'_>,
    protected_names: &[String],
    platform: Platform,
    limit: usize,
) -> Result<ProcessTreeTarget, TreePlanError> {
    let root_info = index.process(root_pid).ok_or(TreePlanError::RootMissing)?;

    let mut nodes = vec![preview_node(root_info, 0, protected_names, platform)];
    let mut seen: HashSet<u32> = HashSet::from([root_pid]);
    let mut frontier = vec![(root_pid, 0_usize)];
    let mut truncated = false;

    while let Some((parent_pid, parent_depth)) = frontier.pop() {
        for &child in index.children(parent_pid) {
            if seen.contains(&child.pid) {
                continue;
            }
            if nodes.len() >= limit {
                truncated = true;
                break;
            }
            seen.insert(child.pid);
            let depth = parent_depth + 1;
            nodes.push(preview_node(child, depth, protected_names, platform));
            frontier.push((child.pid, depth));
        }
        if truncated {
            break;
        }
    }

    nodes.sort_by(|left, right| left.depth.cmp(&right.depth).then(left.pid.cmp(&right.pid)));
    Ok(ProcessTreeTarget {
        nodes,
        truncated,
        limit,
    })
}

/// The previewed process group: its ID plus the member set in the shared
/// preview shape (root at depth 0, every other member at depth 1).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessGroupTarget {
    pgid: u32,
    members: ProcessTreeTarget,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ProcessGroupTarget {
    pub(crate) fn pgid(&self) -> u32 {
        self.pgid
    }

    pub(crate) fn members(&self) -> &ProcessTreeTarget {
        &self.members
    }
}

/// Build the group preview from a single snapshot.
///
/// Pure like the tree preview builder: no signals, no freezing. Membership is one
/// flat filter — every process whose group ID equals the root's — which is why
/// group scope can cover reparented survivors a parent-link walk cannot reach.
/// Rows whose group is `None` are provably non-members: the platforms map only
/// the untargetable kernel group `0` to `None` and fail the scan on anything
/// unreadable.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn plan_process_group(
    root_pid: u32,
    snapshot: &[TreeProcessInfo],
    protected_names: &[String],
    platform: Platform,
    limit: usize,
) -> Result<ProcessGroupTarget, GroupPlanError> {
    let root_info = snapshot
        .iter()
        .find(|info| info.pid == root_pid)
        .ok_or(GroupPlanError::RootMissing)?;
    let Some(pgid) = root_info.process_group else {
        return Err(GroupPlanError::GroupUnavailable);
    };

    let mut nodes = vec![preview_node(root_info, 0, protected_names, platform)];
    let mut members: Vec<&TreeProcessInfo> = snapshot
        .iter()
        .filter(|info| info.process_group == Some(pgid) && info.pid != root_pid)
        .collect();
    members.sort_by_key(|info| info.pid);

    let mut truncated = false;
    for member in members {
        if nodes.len() >= limit {
            truncated = true;
            break;
        }
        nodes.push(preview_node(member, 1, protected_names, platform));
    }

    Ok(ProcessGroupTarget {
        pgid,
        members: ProcessTreeTarget {
            nodes,
            truncated,
            limit,
        },
    })
}

fn preview_node(
    info: &TreeProcessInfo,
    depth: usize,
    protected_names: &[String],
    platform: Platform,
) -> ProcessTreeNode {
    ProcessTreeNode {
        pid: info.pid,
        parent_pid: info.parent_pid,
        parent_process_name: info.parent_process_name.clone(),
        process_name: info.process_name.clone(),
        owner_uid: info.owner_uid,
        protected: is_protected(info, protected_names, platform),
        system_process: is_system(
            info.pid,
            info.parent_pid,
            info.parent_process_name.as_deref(),
            info.process_name.as_deref(),
            platform,
        ),
        depth,
    }
}

fn is_protected(info: &TreeProcessInfo, protected_names: &[String], platform: Platform) -> bool {
    info.process_name
        .as_deref()
        .is_some_and(|name| is_protected_process_name(platform, name, protected_names))
}

fn is_system(
    pid: u32,
    parent_pid: Option<u32>,
    parent_process_name: Option<&str>,
    process_name: Option<&str>,
    platform: Platform,
) -> bool {
    // Parent process name is only consulted on Windows; the Linux/macOS policy
    // reads pid and parent pid, which both the preview snapshot and the frozen
    // set carry.
    SystemProcessCheck {
        platform,
        pid: Some(pid),
        parent_pid,
        process_name,
        parent_process_name,
    }
    .is_system_process()
}

/// A process the pipeline has stopped and recorded, so it can verify identity
/// later and thaw it on abort.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FrozenNode {
    pid: u32,
    parent_pid: Option<u32>,
    parent_process_name: Option<String>,
    process_name: Option<String>,
    owner_uid: Option<u32>,
    /// Identity authorized for termination. This never changes after discovery.
    start_time_marker: Option<ProcessStartMarker>,
    /// Identity observed immediately after this PID accepted `SIGSTOP`, used
    /// only to guard rollback when termination authorization fails.
    rollback_start_time_marker: Option<ProcessStartMarker>,
    /// Whether Kickoutchi observed this process running before its successful
    /// stop submission. Only these members may receive cleanup `SIGCONT`.
    resume_on_cleanup: bool,
    depth: usize,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl FrozenNode {
    fn from_info(info: &TreeProcessInfo, depth: usize) -> Self {
        Self {
            pid: info.pid,
            parent_pid: info.parent_pid,
            parent_process_name: info.parent_process_name.clone(),
            process_name: info.process_name.clone(),
            owner_uid: info.owner_uid,
            start_time_marker: info.start_time_marker,
            rollback_start_time_marker: info.start_time_marker,
            resume_on_cleanup: true,
            depth,
        }
    }
}

/// The scope-specific half of the shared freeze pipeline.
///
/// Tree and group kills share every stage — stop the root first, sweep to a
/// fixed point, verify frozen identities, gate on policy, signal leaves-first —
/// and differ only in what makes a process a member and what post-stop fact
/// proves that membership still holds. Keeping the two answers in one enum
/// keeps the pipeline single-copy and each scope's rules auditable side by
/// side.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepScope {
    /// Members are descendants of the frozen set, discovered over parent
    /// links; identity holds while the parent PID is unchanged.
    Tree,
    /// Members share the target process group; identity holds while the group
    /// is unchanged. The parent PID is deliberately not checked: a member's
    /// parent (outside the group, so never frozen) can exit mid-kill and
    /// reparent the member without affecting its membership.
    Group { pgid: u32 },
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl SweepScope {
    fn member_cap(self) -> usize {
        match self {
            Self::Tree => MAX_TREE_PROCESSES,
            Self::Group { .. } => MAX_GROUP_PROCESSES,
        }
    }

    /// Not-yet-frozen members visible in this snapshot, in deterministic (PID)
    /// order.
    fn unfrozen_members(
        self,
        snapshot: &[TreeProcessInfo],
        index: &ProcessTreeIndex<'_>,
        frozen: &[FrozenNode],
    ) -> Vec<FrozenNode> {
        match self {
            Self::Tree => unfrozen_children(index, frozen),
            Self::Group { pgid } => unfrozen_group_members(snapshot, frozen, pgid),
        }
    }

    /// Whether the fresh read still proves the frozen node's membership.
    fn relation_holds(self, node: &FrozenNode, info: &TreeProcessInfo) -> bool {
        match self {
            Self::Tree => node.depth == 0 || info.parent_pid == node.parent_pid,
            Self::Group { pgid } => info.process_group == Some(pgid),
        }
    }
}

/// What the completed confirmation actually authorized, re-applied to the
/// final frozen set before any terminating signal.
///
/// The confirmation gates run against previews — snapshots taken before the
/// freeze. The frozen set is collected after them and can differ: children
/// fork, a root can `exec` into a different name, processes can join a group.
/// So the two facts the prompt established are re-checked where they can no
/// longer drift — while every member is stopped.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScopeAuthorization {
    /// The protected-root typed confirmation (PID or name) was completed.
    /// When false, a root whose fresh post-stop name is protected refuses the
    /// whole kill — even if its name was unreadable or different at every
    /// earlier check, because `exec` changes the name without changing the
    /// PID, parent, or start marker.
    pub(crate) protected_root_confirmed: bool,
    /// The typed-word prompt was skipped (the `--yes` all-clear path). The
    /// skip was justified by a preview; if the frozen set would no longer
    /// qualify — a system/service member appeared, a different-uid member
    /// appeared, or a group outgrew [`GROUP_YES_SKIP_MAX_PROCESSES`] — the kill
    /// refuses and asks to be rerun with a real prompt.
    pub(crate) prompt_skipped: bool,
}

/// What a report line needs after a completed tree kill.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeKillReport {
    pub(crate) total: usize,
    /// Processes that accepted the terminating signal.
    pub(crate) delivered: usize,
    /// Processes that were already gone or PID-recycled before final delivery.
    pub(crate) already_exited: usize,
    /// PIDs the OS refused to signal (permission).
    pub(crate) denied: Vec<u32>,
    pub(crate) thaw_failed: Vec<u32>,
}

/// The outcome of the whole freeze-first execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TreeKillOutcome {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Completed(TreeKillReport),
    RootAlreadyExited,
    PermissionDenied {
        pid: u32,
    },
    TargetChanged {
        pid: u32,
    },
    Truncated {
        limit: usize,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    SweepPassLimit {
        limit: usize,
    },
    UnsafePid {
        pid: u32,
        reason: UnsafePidReason,
    },
    ProtectedDescendant {
        pid: u32,
        name: Option<String>,
    },
    ProtectedRoot {
        pid: u32,
        name: Option<String>,
    },
    FreshConfirmationRequired,
    OwnershipUnavailable {
        pid: u32,
    },
    PartialMetadata {
        pid: u32,
    },
    SnapshotFailed(String),
    ThawFailed {
        pids: Vec<u32>,
        cause: Box<TreeKillOutcome>,
    },
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TreeKillOutcome {
    pub(crate) fn failure_cause_text(&self) -> String {
        match self {
            Self::Completed(_) => "scoped signal delivery was incomplete".to_owned(),
            Self::RootAlreadyExited => "the root process already exited".to_owned(),
            Self::PermissionDenied { pid } => format!("permission denied for PID {pid}"),
            Self::TargetChanged { pid } => format!("process identity changed at PID {pid}"),
            Self::Truncated { limit } => format!("the process scope exceeded {limit} members"),
            Self::SweepPassLimit { limit } => {
                format!("the process scope did not converge after {limit} freeze passes")
            }
            Self::UnsafePid { pid, reason } => {
                format!("unsafe PID {pid}: {}", reason.message())
            }
            Self::ProtectedDescendant { pid, name } => format!(
                "protected process PID {pid} ({}) entered the scope",
                name.as_deref().unwrap_or("<unknown>")
            ),
            Self::ProtectedRoot { pid, name } => format!(
                "root PID {pid} ({}) became protected",
                name.as_deref().unwrap_or("<unknown>")
            ),
            Self::FreshConfirmationRequired => {
                "the process scope changed after confirmation".to_owned()
            }
            Self::OwnershipUnavailable { pid } => {
                format!("ownership for PID {pid} became unavailable")
            }
            Self::PartialMetadata { pid } => {
                format!("process metadata for PID {pid} was incomplete")
            }
            Self::SnapshotFailed(error) => error.clone(),
            Self::ThawFailed { pids, cause } => format!(
                "{}; cleanup could not continue PID(s) {}",
                cause.failure_cause_text(),
                format_pid_list(pids)
            ),
        }
    }
}

/// Freeze the tree, verify it, and terminate it — root first to stop, root last
/// to signal.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn execute_tree_kill<Ops: TreeProcessOps>(
    root: &KillTarget,
    mode: KillMode,
    protected_names: &[String],
    platform: Platform,
    authorization: ScopeAuthorization,
    ops: &mut Ops,
) -> TreeKillOutcome {
    execute_freeze_kill(
        root,
        SweepScope::Tree,
        mode,
        protected_names,
        platform,
        authorization,
        ops,
    )
}

/// Freeze the process group `pgid`, verify it, and terminate it — the confirmed
/// root first to stop, last to signal. `pgid` is the group the user confirmed;
/// the pipeline re-proves after every stop that each member (root included)
/// still belongs to it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn execute_group_kill<Ops: TreeProcessOps>(
    root: &KillTarget,
    pgid: u32,
    mode: KillMode,
    protected_names: &[String],
    platform: Platform,
    authorization: ScopeAuthorization,
    ops: &mut Ops,
) -> TreeKillOutcome {
    execute_freeze_kill(
        root,
        SweepScope::Group { pgid },
        mode,
        protected_names,
        platform,
        authorization,
        ops,
    )
}

/// The shared freeze-first execution, for both scopes.
///
/// The ordering is the safety contract: `SIGSTOP` the root before enumerating to
/// prevent ordinary forks; sweep the remaining members to a fixed point; verify
/// every frozen identity through pinned or marker-guarded delivery; refuse
/// (thawing) on any uncertainty; then signal tree members
/// deepest-first/root-last, or group members with every terminating signal
/// queued before any continue.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn execute_freeze_kill<Ops: TreeProcessOps>(
    root: &KillTarget,
    scope: SweepScope,
    mode: KillMode,
    protected_names: &[String],
    platform: Platform,
    authorization: ScopeAuthorization,
    ops: &mut Ops,
) -> TreeKillOutcome {
    if let Some(reason) = unsafe_pid_reason(root.pid) {
        return TreeKillOutcome::UnsafePid {
            pid: root.pid,
            reason,
        };
    }

    ops.set_snapshot_scope(match scope {
        SweepScope::Tree => TreeSnapshotScope::Tree { root_pid: root.pid },
        SweepScope::Group { pgid } => TreeSnapshotScope::Group {
            root_pid: root.pid,
            pgid,
        },
    });

    let stop_deadline = ops.stop_acknowledgement_now() + UNIX_STOP_ACKNOWLEDGEMENT_MAX;

    // Stop the root before anything else: while it remains stopped it cannot
    // fork on its own, normally freezing growth before we inspect membership.
    let (rollback_start_time_marker, root_transitioned) =
        match stop_before_deadline(root.pid, stop_deadline, ops) {
            TreeStopResult::Stopped { transitioned } => (
                ops.rollback_identity_after_stop(root.pid, root.process_start_time_marker),
                transitioned,
            ),
            TreeStopResult::NotFound => return TreeKillOutcome::RootAlreadyExited,
            TreeStopResult::Failed {
                cleanup_required: false,
                rollback_start_time_marker: _,
                error,
            } => return tree_stop_error_outcome(root.pid, error),
            TreeStopResult::Failed {
                cleanup_required: true,
                rollback_start_time_marker,
                error,
            } => {
                let rollback_start_time_marker = rollback_start_time_marker.or_else(|| {
                    ops.rollback_identity_after_stop(root.pid, root.process_start_time_marker)
                });
                let root_node = FrozenNode {
                    pid: root.pid,
                    parent_pid: None,
                    parent_process_name: None,
                    process_name: root.process_name.clone(),
                    owner_uid: root.owner_uid,
                    start_time_marker: root.process_start_time_marker,
                    rollback_start_time_marker,
                    resume_on_cleanup: true,
                    depth: 0,
                };
                return refuse_after_thaw(
                    tree_stop_error_outcome(root.pid, error),
                    &[root_node],
                    ops,
                );
            }
        };

    let mut frozen = match verify_root_after_stop(root, scope, rollback_start_time_marker, ops) {
        Ok(mut node) => {
            node.resume_on_cleanup = root_transitioned;
            vec![node]
        }
        Err((outcome, observed_root)) => {
            // Only the root is stopped at this point.
            let root_node = observed_root.map_or_else(
                || FrozenNode {
                    pid: root.pid,
                    parent_pid: None,
                    parent_process_name: None,
                    process_name: root.process_name.clone(),
                    owner_uid: root.owner_uid,
                    start_time_marker: root.process_start_time_marker,
                    rollback_start_time_marker,
                    resume_on_cleanup: root_transitioned,
                    depth: 0,
                },
                |node| *node,
            );
            let mut root_node = root_node;
            root_node.resume_on_cleanup = root_transitioned;
            return refuse_after_thaw(outcome, &[root_node], ops);
        }
    };

    let convergence_snapshot = match freeze_sweep(&mut frozen, scope, stop_deadline, ops) {
        Ok(snapshot) => snapshot,
        Err(outcome) => return refuse_after_thaw(outcome, &frozen, ops),
    };
    if let Err(outcome) = verify_frozen_identities(&mut frozen, scope, &convergence_snapshot) {
        return refuse_after_thaw(outcome, &frozen, ops);
    }
    if let Err(outcome) = prepare_delivery_handles(&frozen, ops) {
        return refuse_after_thaw(outcome, &frozen, ops);
    }
    if let Err(outcome) = verify_fresh_delivery_evidence(&mut frozen, ops) {
        return refuse_after_thaw(outcome, &frozen, ops);
    }
    if let Err(outcome) =
        check_tree_policy(&frozen, scope, authorization, protected_names, platform)
    {
        return refuse_after_thaw(outcome, &frozen, ops);
    }

    TreeKillOutcome::Completed(signal_tree(&mut frozen, scope, mode, ops))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stop_before_deadline<Ops: TreeProcessOps>(
    pid: u32,
    deadline: std::time::Instant,
    ops: &mut Ops,
) -> TreeStopResult {
    if ops.stop_acknowledgement_now() >= deadline {
        return TreeStopResult::Failed {
            cleanup_required: false,
            rollback_start_time_marker: None,
            error: TreeStopError::ObservationFailed(
                "the operation-wide SIGSTOP acknowledgement deadline expired".to_owned(),
            ),
        };
    }
    ops.stop_checked(pid, deadline)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_root_after_stop<Ops: TreeProcessOps>(
    root: &KillTarget,
    scope: SweepScope,
    rollback_start_time_marker: Option<ProcessStartMarker>,
    ops: &mut Ops,
) -> Result<FrozenNode, (TreeKillOutcome, Option<Box<FrozenNode>>)> {
    let snapshot = ops
        .snapshot()
        .map_err(|error| (TreeKillOutcome::SnapshotFailed(error), None))?;
    let Some(info) = snapshot.iter().find(|info| info.pid == root.pid) else {
        return Err((TreeKillOutcome::RootAlreadyExited, None));
    };
    let mut observed = FrozenNode::from_info(info, 0);
    // The post-stop marker is rollback evidence only. Keep the marker that the
    // user authorized as the termination identity even on this refusal path.
    observed.start_time_marker = root.process_start_time_marker;
    observed.rollback_start_time_marker = rollback_start_time_marker;
    if !root_identity_matches(root, info) {
        return Err((
            TreeKillOutcome::TargetChanged { pid: root.pid },
            Some(Box::new(observed)),
        ));
    }
    // For group scope the confirmed group is part of the root's identity: the
    // sweep derives every other member from it, so a root that moved groups
    // between confirmation and freeze would silently retarget the whole kill.
    if let SweepScope::Group { pgid } = scope
        && info.process_group != Some(pgid)
    {
        return Err((
            TreeKillOutcome::TargetChanged { pid: root.pid },
            Some(Box::new(observed)),
        ));
    }
    Ok(observed)
}

/// Strict root identity: both start markers present and equal, and the confirmed
/// name (when known) unchanged. Mirrors the single-kill revalidation so a reused
/// or exec'd PID is refused, not signalled.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn root_identity_matches(root: &KillTarget, info: &TreeProcessInfo) -> bool {
    match (root.process_start_time_marker, info.start_time_marker) {
        (Some(confirmed), Some(fresh)) if confirmed == fresh => {}
        _ => return false,
    }
    if let Some(expected) = root.process_name.as_deref() {
        match info.process_name.as_deref() {
            Some(actual) if actual == expected => {}
            _ => return false,
        }
    }
    true
}

/// Sweep to a fixed point: each pass reads one fresh snapshot and drains it —
/// stopping every not-yet-frozen member the snapshot shows, including members
/// whose parents were only frozen earlier in the same pass. A static tree of
/// any depth therefore freezes in a single pass, because every generation is
/// already present in that one snapshot. Converges because frozen processes
/// cannot fork on their own while they remain stopped. A pass whose snapshot
/// shows nothing new is the pipeline's bounded convergence point; external
/// continuations can still race it. The pass limit bounds churn between
/// snapshots (fresh forks in tree scope, `setpgid` joins in group scope).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn freeze_sweep<Ops: TreeProcessOps>(
    frozen: &mut Vec<FrozenNode>,
    scope: SweepScope,
    stop_deadline: std::time::Instant,
    ops: &mut Ops,
) -> Result<Vec<TreeProcessInfo>, TreeKillOutcome> {
    let member_cap = scope.member_cap();
    for _ in 0..MAX_FREEZE_PASSES {
        let snapshot = ops.snapshot().map_err(TreeKillOutcome::SnapshotFailed)?;
        let index =
            ProcessTreeIndex::new(&snapshot, PROCESS_TREE_INDEX_MAX).map_err(
                |error| match error {
                    TreePlanError::SnapshotLimitExceeded { limit } => {
                        TreeKillOutcome::Truncated { limit }
                    }
                    TreePlanError::RootMissing => {
                        unreachable!("index construction does not resolve roots")
                    }
                },
            )?;
        // Members that exited between this snapshot and our stop attempt. They
        // must be excluded from re-discovery in the same (now stale) snapshot,
        // or the drain below would spin on them; whatever they left behind is
        // picked up by the next pass's fresh snapshot if it still qualifies.
        let mut vanished: HashSet<u32> = HashSet::new();
        let mut discovered_in_pass = false;
        loop {
            let discovered: Vec<FrozenNode> = scope
                .unfrozen_members(&snapshot, &index, frozen)
                .into_iter()
                .filter(|member| !vanished.contains(&member.pid))
                .collect();
            if discovered.is_empty() {
                break;
            }
            discovered_in_pass = true;
            for member in discovered {
                if frozen.len() >= member_cap {
                    return Err(TreeKillOutcome::Truncated { limit: member_cap });
                }
                if let Some(reason) = unsafe_pid_reason(member.pid) {
                    return Err(TreeKillOutcome::UnsafePid {
                        pid: member.pid,
                        reason,
                    });
                }
                if member.start_time_marker.is_none() {
                    return Err(TreeKillOutcome::PartialMetadata { pid: member.pid });
                }
                match stop_before_deadline(member.pid, stop_deadline, ops) {
                    TreeStopResult::Stopped { transitioned } => {
                        let mut member = member;
                        member.rollback_start_time_marker =
                            ops.rollback_identity_after_stop(member.pid, member.start_time_marker);
                        member.resume_on_cleanup = transitioned;
                        frozen.push(member);
                    }
                    TreeStopResult::NotFound => {
                        vanished.insert(member.pid);
                    }
                    TreeStopResult::Failed {
                        cleanup_required: false,
                        rollback_start_time_marker: _,
                        error,
                    } => {
                        return Err(tree_stop_error_outcome(member.pid, error));
                    }
                    TreeStopResult::Failed {
                        cleanup_required: true,
                        rollback_start_time_marker,
                        error,
                    } => {
                        let mut member = member;
                        let pid = member.pid;
                        member.rollback_start_time_marker =
                            rollback_start_time_marker.or_else(|| {
                                ops.rollback_identity_after_stop(
                                    member.pid,
                                    member.start_time_marker,
                                )
                            });
                        member.resume_on_cleanup = true;
                        frozen.push(member);
                        return Err(tree_stop_error_outcome(pid, error));
                    }
                }
            }
        }
        if !discovered_in_pass {
            return Ok(snapshot);
        }
    }
    // Never reached a clean empty pass: the member set kept changing, so we
    // cannot claim to have enumerated it completely.
    Err(TreeKillOutcome::SweepPassLimit {
        limit: MAX_FREEZE_PASSES,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_stop_error_outcome(pid: u32, error: TreeStopError) -> TreeKillOutcome {
    match error {
        TreeStopError::PermissionDenied => TreeKillOutcome::PermissionDenied { pid },
        TreeStopError::ObservationFailed(error) => TreeKillOutcome::SnapshotFailed(error),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unfrozen_children(index: &ProcessTreeIndex<'_>, frozen: &[FrozenNode]) -> Vec<FrozenNode> {
    let frozen_depths: HashMap<u32, usize> =
        frozen.iter().map(|node| (node.pid, node.depth)).collect();
    let mut discovered = Vec::new();
    let mut seen = frozen_depths.keys().copied().collect::<HashSet<_>>();
    let mut frontier = frozen
        .iter()
        .map(|node| (node.pid, node.depth))
        .collect::<Vec<_>>();
    while let Some((parent_pid, parent_depth)) = frontier.pop() {
        for &info in index.children(parent_pid) {
            if !seen.insert(info.pid) {
                continue;
            }
            let depth = parent_depth + 1;
            discovered.push(FrozenNode::from_info(info, depth));
            frontier.push((info.pid, depth));
        }
    }
    discovered.sort_by_key(|node| node.pid);
    discovered
}

/// Group members are a flat filter on the group ID; depth 1 keeps them grouped
/// before the confirmed root in display and delivery order. The group-specific
/// final signal step queues every terminating signal before any `SIGCONT`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unfrozen_group_members(
    snapshot: &[TreeProcessInfo],
    frozen: &[FrozenNode],
    pgid: u32,
) -> Vec<FrozenNode> {
    let frozen_pids: HashSet<u32> = frozen.iter().map(|node| node.pid).collect();
    let mut discovered: Vec<FrozenNode> = snapshot
        .iter()
        .filter(|info| info.process_group == Some(pgid) && !frozen_pids.contains(&info.pid))
        .map(|info| FrozenNode::from_info(info, 1))
        .collect();
    discovered.sort_by_key(|node| node.pid);
    discovered
}

/// Use the snapshot that proved sweep convergence to verify every frozen node.
/// A process that remains stopped cannot exec or exit on its own, so its start
/// marker and scope relation (parent PID for trees, group ID for groups) must be
/// unchanged. External signals can break that assumption; any mismatch refuses.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_frozen_identities(
    frozen: &mut [FrozenNode],
    scope: SweepScope,
    snapshot: &[TreeProcessInfo],
) -> Result<(), TreeKillOutcome> {
    let index = ProcessTreeIndex::new(snapshot, PROCESS_TREE_INDEX_MAX).map_err(|error| {
        TreeKillOutcome::SnapshotFailed(format!("process index construction failed: {error:?}"))
    })?;
    for node in frozen.iter_mut() {
        let Some(info) = index.process(node.pid) else {
            return Err(TreeKillOutcome::TargetChanged { pid: node.pid });
        };
        if info.start_time_marker.is_none() || info.process_name.is_none() {
            return Err(TreeKillOutcome::PartialMetadata { pid: node.pid });
        }
        if !scope.relation_holds(node, info) || info.start_time_marker != node.start_time_marker {
            return Err(TreeKillOutcome::TargetChanged { pid: node.pid });
        }
        node.process_name.clone_from(&info.process_name);
        node.owner_uid = info.owner_uid;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prepare_delivery_handles<Ops: TreeProcessOps>(
    frozen: &[FrozenNode],
    ops: &mut Ops,
) -> Result<(), TreeKillOutcome> {
    for node in frozen {
        match ops.prepare_delivery(node.pid, node.start_time_marker) {
            TreeSignalResult::Delivered => {}
            TreeSignalResult::NotFound => {
                return Err(TreeKillOutcome::TargetChanged { pid: node.pid });
            }
            TreeSignalResult::Denied => {
                return Err(TreeKillOutcome::PermissionDenied { pid: node.pid });
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn verify_fresh_delivery_evidence<Ops: TreeProcessOps>(
    frozen: &mut [FrozenNode],
    ops: &mut Ops,
) -> Result<(), TreeKillOutcome> {
    let mut scope = ProcessEvidenceScope::new(frozen.len()).map_err(evidence_tree_outcome)?;
    for node in frozen {
        let expected = ExpectedProcessEvidence {
            pid: node.pid,
            start_marker: node
                .start_time_marker
                .ok_or(TreeKillOutcome::PartialMetadata { pid: node.pid })?,
            name: None,
        };
        let fresh = scope
            .observe(&expected, ops.fresh_process_evidence(node.pid))
            .map_err(evidence_tree_outcome)?;
        node.process_name = Some(fresh.name);
    }
    scope.finish().map_err(evidence_tree_outcome)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn evidence_tree_outcome(error: ProcessEvidenceError) -> TreeKillOutcome {
    match error {
        ProcessEvidenceError::PermissionDenied { pid } => TreeKillOutcome::PermissionDenied { pid },
        ProcessEvidenceError::IdentityChanged { pid }
        | ProcessEvidenceError::NameChanged { pid }
        | ProcessEvidenceError::Missing { pid } => TreeKillOutcome::TargetChanged { pid },
        ProcessEvidenceError::NameMissing { pid }
        | ProcessEvidenceError::NameOversized { pid, .. } => {
            TreeKillOutcome::PartialMetadata { pid }
        }
        ProcessEvidenceError::IncompleteScope { .. }
        | ProcessEvidenceError::MemberLimitExceeded { .. }
        | ProcessEvidenceError::ByteLimitExceeded { .. } => TreeKillOutcome::SnapshotFailed(
            "fresh process evidence exceeded its bounded scope".to_owned(),
        ),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn check_tree_policy(
    frozen: &[FrozenNode],
    scope: SweepScope,
    authorization: ScopeAuthorization,
    protected_names: &[String],
    platform: Platform,
) -> Result<(), TreeKillOutcome> {
    for node in frozen {
        if let Some(reason) = unsafe_pid_reason(node.pid) {
            return Err(TreeKillOutcome::UnsafePid {
                pid: node.pid,
                reason,
            });
        }
        if node.process_name.is_none() {
            return Err(TreeKillOutcome::PartialMetadata { pid: node.pid });
        }
    }
    // A protected descendant refuses the whole tree in v1.
    for node in frozen.iter().filter(|node| node.depth > 0) {
        if let Some(name) = node.process_name.as_deref()
            && is_protected_process_name(platform, name, protected_names)
        {
            return Err(TreeKillOutcome::ProtectedDescendant {
                pid: node.pid,
                name: Some(name.to_owned()),
            });
        }
    }
    // The root's protection is re-checked against its fresh post-stop name.
    // The confirmation-stage verdict used whatever name was readable then, but
    // `exec` swaps the name without changing the PID, parent, or start marker
    // — and an unknown confirmed name makes the identity check name-blind. So
    // unless the protected-root typed confirmation was actually completed, a
    // root that is protected *now* refuses now.
    if !authorization.protected_root_confirmed
        && let Some(root) = frozen.iter().find(|node| node.depth == 0)
        && let Some(name) = root.process_name.as_deref()
        && is_protected_process_name(platform, name, protected_names)
    {
        return Err(TreeKillOutcome::ProtectedRoot {
            pid: root.pid,
            name: Some(name.to_owned()),
        });
    }
    // A skipped prompt was justified by an all-clear preview. The frozen set
    // may have grown since; if it would no longer justify the skip, refuse and
    // ask for a rerun that actually prompts.
    if authorization.prompt_skipped {
        let system_member_appeared = frozen.iter().any(|node| {
            is_system(
                node.pid,
                node.parent_pid,
                node.parent_process_name.as_deref(),
                node.process_name.as_deref(),
                platform,
            )
        });
        let current_uid = current_user_id();
        let owner_mismatch_member_appeared = frozen.iter().any(|node| {
            node.owner_uid
                .is_some_and(|owner_uid| owner_uid != current_uid)
        });
        let group_outgrew_skip = matches!(scope, SweepScope::Group { .. })
            && frozen.len() > GROUP_YES_SKIP_MAX_PROCESSES;
        if system_member_appeared || owner_mismatch_member_appeared || group_outgrew_skip {
            return Err(TreeKillOutcome::FreshConfirmationRequired);
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn signal_tree<Ops: TreeProcessOps>(
    frozen: &mut [FrozenNode],
    scope: SweepScope,
    mode: KillMode,
    ops: &mut Ops,
) -> TreeKillReport {
    // Leaves first: deepest depth first, root (depth 0) last, PID as a stable
    // tiebreak so the order is deterministic across runs and tests.
    frozen.sort_by(|left, right| right.depth.cmp(&left.depth).then(left.pid.cmp(&right.pid)));

    if matches!(scope, SweepScope::Group { .. }) {
        return signal_group(frozen, mode, ops);
    }

    let total = frozen.len();
    let mut delivered = 0;
    let mut already_exited = 0;
    let mut denied = Vec::new();
    let mut thaw_failed = Vec::new();
    for node in frozen.iter() {
        let result = ops.deliver(node.pid, mode);
        match result {
            TreeSignalResult::Delivered => {
                delivered += 1;
                if mode == KillMode::Terminate && ops.cont(node.pid) == TreeSignalResult::Denied {
                    // SIGTERM remains pending for any stopped process, including
                    // one stopped before Kickoutchi observed it.
                    thaw_failed.push(node.pid);
                }
            }
            TreeSignalResult::NotFound => already_exited += 1,
            TreeSignalResult::Denied => {
                if node.resume_on_cleanup {
                    // A denied signal leaves a process we stopped in need of
                    // cleanup. A process that was already stopped stays stopped.
                    if ops.cont(node.pid) == TreeSignalResult::Denied {
                        thaw_failed.push(node.pid);
                    }
                }
                denied.push(node.pid);
            }
        }
    }

    TreeKillReport {
        total,
        delivered,
        already_exited,
        denied,
        thaw_failed,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn signal_group<Ops: TreeProcessOps>(
    frozen: &[FrozenNode],
    mode: KillMode,
    ops: &mut Ops,
) -> TreeKillReport {
    let total = frozen.len();
    let mut delivered = 0;
    let mut already_exited = 0;
    let mut denied = Vec::new();
    let mut thaw_failed = Vec::new();
    let mut continue_after_delivery = Vec::new();

    for node in frozen {
        match ops.deliver(node.pid, mode) {
            TreeSignalResult::Delivered => {
                delivered += 1;
                if mode == KillMode::Terminate {
                    continue_after_delivery.push(node.pid);
                }
            }
            TreeSignalResult::NotFound => already_exited += 1,
            TreeSignalResult::Denied => {
                denied.push(node.pid);
                if node.resume_on_cleanup {
                    continue_after_delivery.push(node.pid);
                }
            }
        }
    }

    // Group members can have parent/child relationships even though membership
    // is flat. Queue every terminating signal before any member resumes, so a
    // parent cannot wake up and spawn survivors while children are still merely
    // frozen.
    for pid in continue_after_delivery {
        if ops.cont(pid) == TreeSignalResult::Denied {
            thaw_failed.push(pid);
        }
    }

    TreeKillReport {
        total,
        delivered,
        already_exited,
        denied,
        thaw_failed,
    }
}

/// Thaw every member Kickoutchi transitioned and report the ones that may still
/// be stopped. Members observed already stopped are deliberately untouched.
///
/// Only `Denied` counts as a cleanup failure, matching `signal_tree`,
/// `signal_group`, and the single-process `outcome_after_thaw`. `NotFound`
/// means the member is gone — an external `SIGKILL` removed it, or macOS
/// observed a changed start marker — so there is no stopped survivor to
/// report, and naming it would send the user hunting for a process that no
/// longer exists.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn thaw_all<Ops: TreeProcessOps>(frozen: &[FrozenNode], ops: &mut Ops) -> Vec<u32> {
    let mut failed = Vec::new();
    for node in frozen.iter().rev().filter(|node| node.resume_on_cleanup) {
        ops.prepare_thaw(node.pid, node.rollback_start_time_marker);
        if ops.cont(node.pid) == TreeSignalResult::Denied {
            failed.push(node.pid);
        }
    }
    failed.sort_unstable();
    failed
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn refuse_after_thaw<Ops: TreeProcessOps>(
    cause: TreeKillOutcome,
    frozen: &[FrozenNode],
    ops: &mut Ops,
) -> TreeKillOutcome {
    let pids = thaw_all(frozen, ops);
    if pids.is_empty() {
        cause
    } else {
        TreeKillOutcome::ThawFailed {
            pids,
            cause: Box::new(cause),
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use crate::model::PortEntryView;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        FrozenNode, GROUP_YES_SKIP_MAX_PROCESSES, GroupPlanError, MAX_GROUP_PROCESSES,
        MAX_TREE_PROCESSES, PROCESS_TREE_INDEX_MAX, ProcessTreeIndex, ScopeAuthorization,
        TreeKillOutcome, TreePlanError, TreeProcessInfo, TreeProcessOps, TreeSignalResult,
        TreeStopError, TreeStopResult, execute_group_kill, execute_tree_kill, plan_process_group,
        plan_process_tree, verify_frozen_identities,
    };
    use crate::model::{
        PermissionStatus, Platform, PortEntry, ProcessContext, Protocol, SocketState,
    };
    use crate::process::{KillMode, KillTarget};
    use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Stop(u32),
        Cont(u32),
        Deliver(u32, KillMode),
    }

    /// A scripted process table plus a recorded call log.
    ///
    /// `snapshots` are returned in order; the last one repeats for any further
    /// reads, so a test only lists as many distinct tables as its scenario needs.
    struct FakeOps {
        snapshots: Vec<Vec<TreeProcessInfo>>,
        next: usize,
        events: Vec<Event>,
        deny_stop: Vec<u32>,
        pre_stopped: Vec<u32>,
        uncertain_stop: Vec<u32>,
        stop_clock: std::time::Instant,
        stop_elapsed: std::time::Duration,
        stop_deadlines: Vec<std::time::Instant>,
        missing_stop: Vec<u32>,
        missing_deliver: Vec<u32>,
        deny_deliver: Vec<u32>,
        deny_cont: Vec<u32>,
        missing_cont: Vec<u32>,
        rollback_markers_after_stop: HashMap<u32, Option<crate::observation::ProcessStartMarker>>,
        prepared_thaws: HashMap<u32, Option<crate::observation::ProcessStartMarker>>,
        fresh_evidence: HashMap<u32, Result<FreshProcessEvidence, ProcessEvidenceError>>,
    }

    impl FakeOps {
        fn new(snapshots: Vec<Vec<TreeProcessInfo>>) -> Self {
            Self {
                snapshots,
                next: 0,
                events: Vec::new(),
                deny_stop: Vec::new(),
                pre_stopped: Vec::new(),
                uncertain_stop: Vec::new(),
                stop_clock: std::time::Instant::now(),
                stop_elapsed: std::time::Duration::ZERO,
                stop_deadlines: Vec::new(),
                missing_stop: Vec::new(),
                missing_deliver: Vec::new(),
                deny_deliver: Vec::new(),
                deny_cont: Vec::new(),
                missing_cont: Vec::new(),
                rollback_markers_after_stop: HashMap::new(),
                prepared_thaws: HashMap::new(),
                fresh_evidence: HashMap::new(),
            }
        }

        fn delivered_pids(&self) -> Vec<u32> {
            self.events
                .iter()
                .filter_map(|event| match event {
                    Event::Deliver(pid, _) => Some(*pid),
                    _ => None,
                })
                .collect()
        }
    }

    impl TreeProcessOps for FakeOps {
        fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
            let index = self.next.min(self.snapshots.len().saturating_sub(1));
            self.next += 1;
            Ok(self.snapshots.get(index).cloned().unwrap_or_default())
        }

        fn stop(&mut self, pid: u32) -> TreeSignalResult {
            self.events.push(Event::Stop(pid));
            if self.deny_stop.contains(&pid) {
                return TreeSignalResult::Denied;
            }
            if self.missing_stop.contains(&pid) {
                return TreeSignalResult::NotFound;
            }
            TreeSignalResult::Delivered
        }

        fn stop_checked(&mut self, pid: u32, deadline: std::time::Instant) -> TreeStopResult {
            self.stop_deadlines.push(deadline);
            self.stop_clock += self.stop_elapsed;
            if self.stop_clock >= deadline {
                return TreeStopResult::Failed {
                    cleanup_required: false,
                    rollback_start_time_marker: None,
                    error: TreeStopError::ObservationFailed(
                        "the operation-wide SIGSTOP acknowledgement deadline expired".to_owned(),
                    ),
                };
            }
            match self.stop(pid) {
                TreeSignalResult::Delivered if self.uncertain_stop.contains(&pid) => {
                    TreeStopResult::Failed {
                        cleanup_required: true,
                        rollback_start_time_marker: self
                            .rollback_markers_after_stop
                            .get(&pid)
                            .copied()
                            .flatten(),
                        error: TreeStopError::ObservationFailed(
                            "stopped-state observation failed".to_owned(),
                        ),
                    }
                }
                TreeSignalResult::Delivered => TreeStopResult::Stopped {
                    transitioned: !self.pre_stopped.contains(&pid),
                },
                TreeSignalResult::NotFound => TreeStopResult::NotFound,
                TreeSignalResult::Denied => TreeStopResult::Failed {
                    cleanup_required: false,
                    rollback_start_time_marker: None,
                    error: TreeStopError::PermissionDenied,
                },
            }
        }

        fn stop_acknowledgement_now(&self) -> std::time::Instant {
            self.stop_clock
        }

        fn rollback_identity_after_stop(
            &mut self,
            pid: u32,
            prior_marker: Option<crate::observation::ProcessStartMarker>,
        ) -> Option<crate::observation::ProcessStartMarker> {
            self.rollback_markers_after_stop
                .get(&pid)
                .copied()
                .unwrap_or(prior_marker)
        }

        fn cont(&mut self, pid: u32) -> TreeSignalResult {
            self.events.push(Event::Cont(pid));
            if self.deny_cont.contains(&pid) {
                TreeSignalResult::Denied
            } else if self.missing_cont.contains(&pid) {
                TreeSignalResult::NotFound
            } else {
                TreeSignalResult::Delivered
            }
        }

        fn prepare_thaw(
            &mut self,
            pid: u32,
            marker: Option<crate::observation::ProcessStartMarker>,
        ) {
            self.prepared_thaws.insert(pid, marker);
        }

        fn prepare_delivery(
            &mut self,
            _pid: u32,
            _verified_start_marker: Option<crate::observation::ProcessStartMarker>,
        ) -> TreeSignalResult {
            TreeSignalResult::Delivered
        }

        fn fresh_process_evidence(
            &mut self,
            pid: u32,
        ) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
            if let Some(evidence) = self.fresh_evidence.get(&pid) {
                return evidence.clone();
            }
            let snapshot = self
                .snapshot()
                .map_err(|_| ProcessEvidenceError::Missing { pid })?;
            let info = snapshot
                .iter()
                .find(|info| info.pid == pid)
                .ok_or(ProcessEvidenceError::Missing { pid })?;
            Ok(FreshProcessEvidence {
                pid,
                start_marker: info
                    .start_time_marker
                    .ok_or(ProcessEvidenceError::Missing { pid })?,
                name: info
                    .process_name
                    .clone()
                    .ok_or(ProcessEvidenceError::NameMissing { pid })?,
            })
        }

        fn deliver(&mut self, pid: u32, mode: KillMode) -> TreeSignalResult {
            self.events.push(Event::Deliver(pid, mode));
            if self.missing_deliver.contains(&pid) {
                return TreeSignalResult::NotFound;
            }
            if self.deny_deliver.contains(&pid) {
                return TreeSignalResult::Denied;
            }
            TreeSignalResult::Delivered
        }
    }

    #[test]
    fn refusal_prepares_verified_identity_before_each_thaw() {
        let marker = crate::observation::ProcessStartMarker::linux(55).ok();
        let frozen = [FrozenNode {
            pid: 42,
            parent_pid: None,
            parent_process_name: None,
            process_name: Some("node".to_owned()),
            owner_uid: None,
            start_time_marker: marker,
            rollback_start_time_marker: marker,
            resume_on_cleanup: true,
            depth: 0,
        }];
        let mut ops = FakeOps::new(Vec::new());

        assert!(super::thaw_all(&frozen, &mut ops).is_empty());
        assert_eq!(ops.prepared_thaws.get(&42), Some(&marker));
        assert_eq!(ops.events, [Event::Cont(42)]);
    }

    /// A member that vanished under the freeze leaves nothing stopped, so it
    /// must not be named as a thaw failure — that would send the user chasing
    /// a PID that no longer exists. Only a refused `SIGCONT` is a real failure.
    /// This pins the same `Denied`-only rule the delivery paths and the
    /// single-process `outcome_after_thaw` already use.
    #[test]
    fn refusal_reports_only_denied_continuations_as_thaw_failures() {
        let marker = crate::observation::ProcessStartMarker::linux(55).ok();
        let node = |pid| FrozenNode {
            pid,
            parent_pid: None,
            parent_process_name: None,
            process_name: Some("node".to_owned()),
            owner_uid: None,
            start_time_marker: marker,
            rollback_start_time_marker: marker,
            resume_on_cleanup: true,
            depth: 0,
        };
        let frozen = [node(42), node(43)];
        let mut ops = FakeOps::new(Vec::new());
        ops.missing_cont.push(42);
        ops.deny_cont.push(43);

        assert_eq!(super::thaw_all(&frozen, &mut ops), [43]);
        assert_eq!(ops.prepared_thaws.get(&42), Some(&marker));
        assert_eq!(ops.prepared_thaws.get(&43), Some(&marker));
        // Both members are still attempted, deepest-first, even though only one
        // is reported.
        assert_eq!(ops.events, [Event::Cont(43), Event::Cont(42)]);
    }

    #[test]
    fn refusal_does_not_resume_members_that_were_already_stopped() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "postgres", 11),
        ];
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);
        ops.pre_stopped.push(101);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &["postgres".to_owned()],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert!(matches!(
            outcome,
            TreeKillOutcome::ProtectedDescendant { pid: 101, .. }
        ));
        assert!(ops.events.contains(&Event::Cont(100)));
        assert!(!ops.events.contains(&Event::Cont(101)));
    }

    #[test]
    fn later_refusal_does_not_resume_a_root_that_was_already_stopped() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "postgres", 11),
        ];
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);
        ops.pre_stopped.push(100);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &["postgres".to_owned()],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert!(matches!(
            outcome,
            TreeKillOutcome::ProtectedDescendant { pid: 101, .. }
        ));
        assert!(ops.events.contains(&Event::Cont(101)));
        assert!(!ops.events.contains(&Event::Cont(100)));
    }

    #[test]
    fn successful_terminate_resumes_a_previously_stopped_member_after_delivery() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "child", 11),
        ];
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);
        ops.pre_stopped.push(101);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert!(matches!(outcome, TreeKillOutcome::Completed(_)));
        let delivered = ops
            .events
            .iter()
            .position(|event| *event == Event::Deliver(101, KillMode::Terminate))
            .expect("child receives SIGTERM");
        let continued = ops
            .events
            .iter()
            .position(|event| *event == Event::Cont(101))
            .expect("child is resumed so pending SIGTERM can run");
        assert!(delivered < continued);
    }

    #[test]
    fn failed_stopped_state_observation_still_rolls_back_submitted_stop() {
        let root = root_target(100, "root", 10);
        let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "root", 10)]]);
        ops.uncertain_stop.push(100);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(
            outcome,
            TreeKillOutcome::SnapshotFailed("stopped-state observation failed".to_owned())
        );
        assert_eq!(ops.events, [Event::Stop(100), Event::Cont(100)]);
        assert!(ops.delivered_pids().is_empty());
    }

    #[test]
    fn identity_change_after_stop_retains_cleanup_for_the_observed_replacement() {
        let root = root_target(100, "root", 10);
        let replacement = crate::observation::ProcessStartMarker::linux(999).ok();
        let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "root", 10)]]);
        ops.uncertain_stop.push(100);
        ops.rollback_markers_after_stop.insert(100, replacement);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Macos,
            auth(),
            &mut ops,
        );

        assert_eq!(
            outcome,
            TreeKillOutcome::SnapshotFailed("stopped-state observation failed".to_owned())
        );
        assert_eq!(ops.prepared_thaws.get(&100), Some(&replacement));
        assert_eq!(ops.events, [Event::Stop(100), Event::Cont(100)]);
    }

    #[test]
    fn stop_acknowledgements_share_one_operation_deadline() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "first", 11),
            info(102, Some(100), "second", 12),
        ];
        let mut ops = FakeOps::new(vec![snapshot]);
        ops.stop_elapsed = std::time::Duration::from_millis(100);
        let expected_deadline = ops.stop_clock + crate::process::UNIX_STOP_ACKNOWLEDGEMENT_MAX;

        let outcome = execute_tree_kill(
            &root,
            KillMode::Force,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert!(matches!(outcome, TreeKillOutcome::Completed(_)));
        assert_eq!(
            ops.stop_deadlines,
            [expected_deadline, expected_deadline, expected_deadline]
        );
    }

    #[test]
    fn pre_signal_delay_past_shared_deadline_sends_no_stop() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![info(100, Some(1), "root", 10)];
        let mut ops = FakeOps::new(vec![snapshot]);
        ops.stop_elapsed = crate::process::UNIX_STOP_ACKNOWLEDGEMENT_MAX;
        let expected_deadline = ops.stop_clock + crate::process::UNIX_STOP_ACKNOWLEDGEMENT_MAX;

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(
            outcome,
            TreeKillOutcome::SnapshotFailed(
                "the operation-wide SIGSTOP acknowledgement deadline expired".to_owned()
            )
        );
        assert!(
            ops.events.is_empty(),
            "SIGSTOP must not be sent at the deadline"
        );
        assert_eq!(ops.stop_deadlines, [expected_deadline]);
    }

    #[test]
    fn root_delay_consumes_shared_deadline_before_descendant_stop() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "child", 11),
        ];
        let mut ops = FakeOps::new(vec![snapshot]);
        ops.stop_elapsed = std::time::Duration::from_millis(250);
        let expected_deadline = ops.stop_clock + crate::process::UNIX_STOP_ACKNOWLEDGEMENT_MAX;

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(
            outcome,
            TreeKillOutcome::SnapshotFailed(
                "the operation-wide SIGSTOP acknowledgement deadline expired".to_owned()
            )
        );
        assert_eq!(ops.events, [Event::Stop(100), Event::Cont(100)]);
        assert_eq!(ops.stop_deadlines, [expected_deadline, expected_deadline]);
    }

    #[test]
    fn scoped_thaw_failure_text_retains_the_primary_failure() {
        let outcome = TreeKillOutcome::ThawFailed {
            pids: vec![100],
            cause: Box::new(TreeKillOutcome::PermissionDenied { pid: 101 }),
        };

        assert_eq!(
            outcome.failure_cause_text(),
            "permission denied for PID 101; cleanup could not continue PID(s) 100"
        );
    }

    #[test]
    fn stopped_replacement_uses_immediate_identity_when_later_member_refuses() {
        let root = root_target(100, "root", 10);
        let root_snapshot = vec![info(100, None, "root", 10)];
        let mut partial = info(102, Some(100), "partial", 12);
        partial.start_time_marker = None;
        let sweep_snapshot = vec![
            info(100, None, "root", 10),
            info(101, Some(100), "child", 11),
            partial,
        ];
        let replacement_marker = crate::observation::ProcessStartMarker::linux(777).ok();
        let mut ops = FakeOps::new(vec![root_snapshot, sweep_snapshot]);
        ops.rollback_markers_after_stop
            .insert(101, replacement_marker);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::PartialMetadata { pid: 102 });
        assert_eq!(ops.prepared_thaws.get(&101), Some(&replacement_marker));
        assert_eq!(
            ops.events,
            [
                Event::Stop(100),
                Event::Stop(101),
                Event::Cont(101),
                Event::Cont(100),
            ]
        );
        assert!(ops.delivered_pids().is_empty());
    }

    fn info(pid: u32, parent: Option<u32>, name: &str, marker: u64) -> TreeProcessInfo {
        TreeProcessInfo {
            pid,
            parent_pid: parent,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some(name.into()),
            start_time_marker: crate::observation::ProcessStartMarker::linux(marker).ok(),
            owner_uid: None,
            process_group: None,
        }
    }

    #[test]
    fn process_tree_index_accepts_exact_limit_and_rejects_max_plus_one() {
        let exact = vec![
            info(3, Some(1), "three", 3),
            info(1, None, "one", 1),
            info(2, Some(1), "two", 2),
        ];
        let index = ProcessTreeIndex::new(&exact, 3).expect("exact index limit is accepted");
        assert_eq!(index.process(2).map(|process| process.pid), Some(2));
        assert_eq!(
            index
                .children(1)
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>(),
            [2, 3]
        );

        let error = ProcessTreeIndex::new(&exact, 2).expect_err("max plus one is rejected");
        assert_eq!(error, TreePlanError::SnapshotLimitExceeded { limit: 2 });
    }

    #[test]
    fn production_index_bound_is_wired_through_planning_and_final_verification() {
        let mut exact = Vec::with_capacity(PROCESS_TREE_INDEX_MAX + 1);
        exact.push(info(2, None, "root", 2));
        for offset in 1..PROCESS_TREE_INDEX_MAX {
            let pid = u32::try_from(offset + 2).expect("production index bound fits u32");
            exact.push(TreeProcessInfo {
                pid,
                parent_pid: None,
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: None,
                start_time_marker: None,
                owner_uid: None,
                process_group: None,
            });
        }

        let preview = plan_process_tree(2, &exact, &[], Platform::Linux, MAX_TREE_PROCESSES)
            .expect("exact production index maximum plans");
        assert_eq!(preview.len(), 1);
        assert!(!preview.truncated());

        let root = FrozenNode::from_info(&exact[0], 0);
        let mut frozen = [root];
        verify_frozen_identities(&mut frozen, super::SweepScope::Tree, &exact)
            .expect("exact production index maximum verifies");

        exact.push(TreeProcessInfo {
            pid: u32::MAX,
            parent_pid: None,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: None,
            start_time_marker: None,
            owner_uid: None,
            process_group: None,
        });
        assert_eq!(
            plan_process_tree(2, &exact, &[], Platform::Linux, MAX_TREE_PROCESSES),
            Err(TreePlanError::SnapshotLimitExceeded {
                limit: PROCESS_TREE_INDEX_MAX
            })
        );
        assert!(matches!(
            verify_frozen_identities(&mut frozen, super::SweepScope::Tree, &exact),
            Err(TreeKillOutcome::SnapshotFailed(message))
                if message.contains("process index construction failed")
        ));
    }

    /// Authorization for the common test case: no protected-root confirmation
    /// completed, and the typed-word prompt actually answered (not skipped).
    fn auth() -> ScopeAuthorization {
        ScopeAuthorization {
            protected_root_confirmed: false,
            prompt_skipped: false,
        }
    }

    fn root_target(pid: u32, name: &str, marker: u64) -> KillTarget {
        let entry = PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: Some(pid),
            process_name: Some(name.into()),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: Some(crate::observation::ProcessIdentity {
                pid,
                start_marker: crate::observation::ProcessStartMarker::linux(marker)
                    .expect("test marker is nonzero"),
            }),
            ipv6_scope: None,
        };
        let context = ProcessContext {
            process_start_time_marker: crate::observation::ProcessStartMarker::linux(marker).ok(),
            ..ProcessContext::default()
        };
        KillTarget::from_entries(pid, [PortEntryView::from(&entry)], Some(&context))
    }

    #[test]
    fn preview_builds_depth_ordered_tree_and_flags_policy() {
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "worker", 11),
            info(102, Some(101), "postgres", 12),
        ];

        let tree = plan_process_tree(
            100,
            &snapshot,
            &["postgres".to_owned()],
            Platform::Linux,
            256,
        )
        .expect("root is present");

        assert_eq!(tree.len(), 3);
        assert_eq!(tree.root().map(|node| node.pid), Some(100));
        // The protected descendant is discoverable for the pre-flight refusal.
        assert_eq!(
            tree.protected_descendants().map(|node| node.pid).next(),
            Some(102),
        );
        assert!(!tree.truncated());
    }

    #[test]
    fn root_protection_gate_requires_completed_confirmation() {
        use super::root_protection_outcome;

        let protected_root = plan_process_tree(
            100,
            &[info(100, Some(500), "postgres", 10)],
            &["postgres".to_owned()],
            Platform::Linux,
            256,
        )
        .expect("root present");
        // Without the completed protected confirmation, a protected root
        // refuses and names itself; with it, the same tree proceeds.
        assert_eq!(
            root_protection_outcome(&protected_root, false),
            Err(TreeKillOutcome::ProtectedRoot {
                pid: 100,
                name: Some("postgres".to_owned()),
            }),
        );
        assert_eq!(root_protection_outcome(&protected_root, true), Ok(()));

        let plain_root = plan_process_tree(
            100,
            &[info(100, Some(500), "node", 10)],
            &["postgres".to_owned()],
            Platform::Linux,
            256,
        )
        .expect("root present");
        assert_eq!(root_protection_outcome(&plain_root, false), Ok(()));
    }

    #[test]
    fn preview_truncates_at_the_limit_without_erroring() {
        let mut snapshot = vec![info(100, Some(1), "root", 10)];
        for pid in 200..210 {
            snapshot.push(info(pid, Some(100), "child", u64::from(pid)));
        }

        let tree =
            plan_process_tree(100, &snapshot, &[], Platform::Linux, 4).expect("root is present");

        assert_eq!(tree.len(), 4);
        assert!(tree.truncated());
    }

    #[test]
    fn single_root_terminates_with_term_then_cont() {
        let root = root_target(100, "node", 10);
        let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "node", 10)]]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completion, got {outcome:?}");
        };
        assert_eq!(report.total, 1);
        assert_eq!(report.delivered, 1);
        // Stop first, terminate last, continue after terminate.
        assert_eq!(
            ops.events,
            vec![
                Event::Stop(100),
                Event::Deliver(100, KillMode::Terminate),
                Event::Cont(100),
            ],
        );
    }

    #[test]
    fn spawner_converges_and_kills_leaves_first() {
        let root = root_target(100, "root", 10);
        // The child (101) spawns a grandchild (102) that only appears in a later
        // sweep — the fixed point must still catch it.
        let base = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "child", 11),
        ];
        let grown = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "child", 11),
            info(102, Some(101), "grandchild", 12),
        ];
        let mut ops = FakeOps::new(vec![
            base.clone(),  // verify root
            base,          // sweep pass 1: discovers 101
            grown.clone(), // sweep pass 2: discovers 102
            grown.clone(), // sweep pass 3: no new -> converged
            grown,         // final identity verify
        ]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completion, got {outcome:?}");
        };
        assert_eq!(report.total, 3);
        // Deepest first, root last.
        assert_eq!(ops.delivered_pids(), vec![102, 101, 100]);
    }

    #[test]
    fn force_mode_kills_without_continue() {
        let root = root_target(100, "node", 10);
        let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "node", 10)]]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Force,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert!(matches!(outcome, TreeKillOutcome::Completed(_)));
        // No SIGCONT after SIGKILL.
        assert_eq!(
            ops.events,
            vec![Event::Stop(100), Event::Deliver(100, KillMode::Force)],
        );
    }

    #[test]
    fn stopped_root_replacement_is_refused_but_prepared_for_rollback() {
        let root = root_target(100, "node", 10);
        // Same PID, different start marker: a reused PID. Refuse, and thaw.
        let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "node", 999)]]);
        ops.rollback_markers_after_stop
            .insert(100, crate::observation::ProcessStartMarker::linux(999).ok());

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::TargetChanged { pid: 100 });
        assert_eq!(ops.events, vec![Event::Stop(100), Event::Cont(100)]);
        assert_eq!(
            ops.prepared_thaws.get(&100),
            Some(&crate::observation::ProcessStartMarker::linux(999).ok())
        );
        assert!(ops.delivered_pids().is_empty());
    }

    #[test]
    fn all_stopped_descendant_replacements_are_prepared_before_first_refusal() {
        let root = root_target(100, "root", 10);
        let stable = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "first-child", 11),
            info(102, Some(100), "second-child", 12),
        ];
        // Both stops landed on replacements. Validation fails on 101 first,
        // but rollback must already retain both immediately observed identities.
        let drifted = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "first-child", 777),
            info(102, Some(100), "second-child", 888),
        ];
        let mut ops = FakeOps::new(vec![
            stable.clone(), // verify root
            stable,         // sweep pass 1: discovers both children
            drifted,        // sweep pass 2: converged and verifies drift
        ]);
        ops.rollback_markers_after_stop
            .insert(101, crate::observation::ProcessStartMarker::linux(777).ok());
        ops.rollback_markers_after_stop
            .insert(102, crate::observation::ProcessStartMarker::linux(888).ok());

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::TargetChanged { pid: 101 });
        assert!(ops.delivered_pids().is_empty());
        assert_eq!(
            ops.prepared_thaws,
            HashMap::from([
                (100, crate::observation::ProcessStartMarker::linux(10).ok()),
                (101, crate::observation::ProcessStartMarker::linux(777).ok()),
                (102, crate::observation::ProcessStartMarker::linux(888).ok()),
            ])
        );
        assert_eq!(
            ops.events,
            vec![
                Event::Stop(100),
                Event::Stop(101),
                Event::Stop(102),
                Event::Cont(102),
                Event::Cont(101),
                Event::Cont(100)
            ],
        );
    }

    #[test]
    fn protected_descendant_thaws_and_refuses() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "postgres", 11),
        ];
        let mut ops = FakeOps::new(vec![
            snapshot.clone(),
            snapshot.clone(),
            snapshot.clone(),
            snapshot,
        ]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &["postgres".to_owned()],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(
            outcome,
            TreeKillOutcome::ProtectedDescendant {
                pid: 101,
                name: Some("postgres".to_owned()),
            },
        );
        assert!(ops.delivered_pids().is_empty());
        assert_eq!(
            ops.events,
            vec![
                Event::Stop(100),
                Event::Stop(101),
                Event::Cont(101),
                Event::Cont(100)
            ],
        );
    }

    #[test]
    fn tree_thaw_failure_attempts_every_member_and_reports_survivors() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "postgres", 11),
        ];
        let mut ops = FakeOps::new(vec![
            snapshot.clone(),
            snapshot.clone(),
            snapshot.clone(),
            snapshot,
        ]);
        ops.deny_cont.extend([100, 101]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &["postgres".to_owned()],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert!(matches!(
            outcome,
            TreeKillOutcome::ThawFailed { ref pids, .. } if pids == &[100, 101]
        ));
        assert!(ops.events.contains(&Event::Cont(100)));
        assert!(ops.events.contains(&Event::Cont(101)));
        assert!(ops.delivered_pids().is_empty());
    }

    #[test]
    fn group_thaw_failure_is_typed_and_visible() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            ginfo(100, Some(1), "root", 10, 77),
            ginfo(101, Some(1), "postgres", 11, 77),
        ];
        let mut ops = FakeOps::new(vec![
            snapshot.clone(),
            snapshot.clone(),
            snapshot.clone(),
            snapshot,
        ]);
        ops.deny_cont.push(101);

        let outcome = execute_group_kill(
            &root,
            77,
            KillMode::Terminate,
            &["postgres".to_owned()],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert!(matches!(
            outcome,
            TreeKillOutcome::ThawFailed { ref pids, .. } if pids == &[101]
        ));
        assert!(ops.events.contains(&Event::Cont(100)));
        assert!(ops.events.contains(&Event::Cont(101)));
    }

    #[test]
    fn cap_exceeded_during_freeze_thaws_and_refuses() {
        let root = root_target(100, "root", 10);
        let mut snapshot = vec![info(100, Some(1), "root", 10)];
        for pid in 200..(200 + u32::try_from(MAX_TREE_PROCESSES).unwrap() + 5) {
            snapshot.push(info(pid, Some(100), "child", u64::from(pid)));
        }
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(
            outcome,
            TreeKillOutcome::Truncated {
                limit: MAX_TREE_PROCESSES,
            },
        );
        assert!(ops.delivered_pids().is_empty());
        // Everything stopped so far was thawed — the same PIDs, not just the
        // same number of signals.
        let mut stopped: Vec<u32> = ops
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Stop(pid) => Some(*pid),
                _ => None,
            })
            .collect();
        let mut continued: Vec<u32> = ops
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Cont(pid) => Some(*pid),
                _ => None,
            })
            .collect();
        stopped.sort_unstable();
        continued.sort_unstable();
        assert_eq!(stopped, continued);
    }

    #[test]
    fn unsafe_descendant_refuses_before_stop_and_thaws_root() {
        let root = root_target(100, "root", 10);
        let unsafe_pid = std::process::id();
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(unsafe_pid, Some(100), "kickoutchi", 11),
        ];
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert!(matches!(outcome, TreeKillOutcome::UnsafePid { pid, .. } if pid == unsafe_pid));
        assert_eq!(ops.events, vec![Event::Stop(100), Event::Cont(100)]);
    }

    #[test]
    fn missing_descendant_start_marker_thaws_and_refuses() {
        let root = root_target(100, "root", 10);
        let mut child = info(101, Some(100), "child", 11);
        child.start_time_marker = None;
        let snapshot = vec![info(100, Some(1), "root", 10), child];
        let mut ops = FakeOps::new(vec![
            snapshot.clone(),
            snapshot.clone(),
            snapshot.clone(),
            snapshot,
        ]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::PartialMetadata { pid: 101 });
        assert!(ops.delivered_pids().is_empty());
        assert_eq!(ops.events, [Event::Stop(100), Event::Cont(100)]);
    }

    #[test]
    fn markerless_descendant_refuses_before_stop_and_thaws_prior_members() {
        let root = root_target(100, "root", 10);
        let mut markerless = info(102, Some(101), "grandchild", 12);
        markerless.start_time_marker = None;
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "child", 11),
            markerless,
        ];
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::PartialMetadata { pid: 102 });
        assert_eq!(
            ops.events,
            [
                Event::Stop(100),
                Event::Stop(101),
                Event::Cont(101),
                Event::Cont(100),
            ]
        );
        assert_eq!(
            ops.prepared_thaws,
            HashMap::from([
                (100, crate::observation::ProcessStartMarker::linux(10).ok()),
                (101, crate::observation::ProcessStartMarker::linux(11).ok()),
            ])
        );
    }

    #[test]
    fn force_delivery_denial_thaws_the_denied_member() {
        let root = root_target(100, "node", 10);
        let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "node", 10)]]);
        ops.deny_deliver.push(100);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Force,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completion report, got {outcome:?}");
        };
        assert_eq!(report.denied, vec![100]);
        assert_eq!(
            ops.events,
            vec![
                Event::Stop(100),
                Event::Deliver(100, KillMode::Force),
                Event::Cont(100)
            ],
        );
    }

    #[test]
    fn post_delivery_thaw_failure_is_retained_in_the_completion_report() {
        let root = root_target(100, "node", 10);
        let mut ops = FakeOps::new(vec![vec![info(100, Some(1), "node", 10)]]);
        ops.deny_cont.push(100);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("delivery completed and cleanup failure must remain reportable");
        };
        assert_eq!(report.delivered, 1);
        assert!(report.denied.is_empty());
        assert_eq!(report.thaw_failed, vec![100]);
        assert_eq!(
            ops.events,
            vec![
                Event::Stop(100),
                Event::Deliver(100, KillMode::Terminate),
                Event::Cont(100)
            ]
        );
    }

    #[test]
    fn final_delivery_not_found_is_reported_separately_from_sent_signals() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "child", 11),
        ];
        let mut ops = FakeOps::new(vec![snapshot]);
        ops.missing_deliver.push(101);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completion report, got {outcome:?}");
        };
        assert_eq!(report.total, 2);
        assert_eq!(report.delivered, 1);
        assert_eq!(report.already_exited, 1);
        assert!(report.denied.is_empty());
    }

    #[test]
    fn root_already_exited_sends_nothing() {
        let root = root_target(100, "node", 10);
        let mut ops = FakeOps::new(vec![vec![]]);
        ops.missing_stop.push(100);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::RootAlreadyExited);
        assert_eq!(ops.events, vec![Event::Stop(100)]);
    }

    #[test]
    fn denied_descendant_stop_thaws_root_and_refuses() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "child", 11),
        ];
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);
        ops.deny_stop.push(101);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::PermissionDenied { pid: 101 });
        assert!(ops.delivered_pids().is_empty());
        assert!(ops.events.contains(&Event::Cont(100)));
    }

    /// `info` with a real process group, for group-scope scenarios.
    fn ginfo(
        pid: u32,
        parent: Option<u32>,
        name: &str,
        marker: u64,
        group: u32,
    ) -> TreeProcessInfo {
        TreeProcessInfo {
            process_group: Some(group),
            ..info(pid, parent, name, marker)
        }
    }

    #[test]
    fn group_plan_is_a_flat_member_set_with_the_root_first() {
        let snapshot = vec![
            ginfo(100, Some(1), "root", 10, 42),
            // In the group but NOT a descendant — the case group scope exists for.
            ginfo(150, Some(1), "orphan", 11, 42),
            // Lower PID than the root: display order is still root first.
            ginfo(90, Some(1), "worker", 12, 42),
            // Same parent, different group: not a member.
            ginfo(300, Some(1), "outsider", 13, 77),
            // Kernel-domain row (no targetable group): provably not a member.
            info(2, None, "kthreadd", 14),
        ];

        let group = plan_process_group(100, &snapshot, &[], Platform::Linux, 512)
            .expect("root is present with a group");

        assert_eq!(group.pgid(), 42);
        assert_eq!(group.members().len(), 3);
        assert_eq!(group.members().root().map(|node| node.pid), Some(100));
        let order: Vec<u32> = group
            .members()
            .preview_nodes(usize::MAX)
            .iter()
            .map(|node| node.pid)
            .collect();
        assert_eq!(order, vec![100, 90, 150]);
        assert!(!group.members().truncated());
    }

    #[test]
    fn group_plan_refuses_missing_roots_and_untargetable_groups() {
        let kernel_rooted = vec![info(100, None, "kthread", 10)];
        assert_eq!(
            plan_process_group(100, &kernel_rooted, &[], Platform::Linux, 512),
            Err(GroupPlanError::GroupUnavailable),
        );
        assert_eq!(
            plan_process_group(4242, &kernel_rooted, &[], Platform::Linux, 512),
            Err(GroupPlanError::RootMissing),
        );
    }

    #[test]
    fn group_plan_truncates_at_its_own_limit_and_preflight_names_it() {
        let mut snapshot = vec![ginfo(100, Some(1), "root", 10, 42)];
        for pid in 200..210 {
            snapshot.push(ginfo(pid, Some(1), "member", u64::from(pid), 42));
        }

        let group = plan_process_group(100, &snapshot, &[], Platform::Linux, 4)
            .expect("root is present with a group");

        assert_eq!(group.members().len(), 4);
        assert!(group.members().truncated());
        // The refusal must carry the cap the builder actually used, not the
        // tree cap: the two scopes have different limits.
        assert_eq!(
            super::preflight_outcome(group.members()),
            Err(TreeKillOutcome::Truncated { limit: 4 }),
        );
    }

    #[test]
    fn group_kill_reaches_a_reparented_member_and_signals_the_root_last() {
        let root = root_target(100, "root", 10);
        // The orphan double-forked away long ago: parent 1, same group. A tree
        // kill from 100 could never reach it; the group kill must.
        let snapshot = vec![
            ginfo(100, Some(1), "root", 10, 42),
            ginfo(150, Some(1), "orphan", 11, 42),
        ];
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot.clone(), snapshot]);

        let outcome = execute_group_kill(
            &root,
            42,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completion, got {outcome:?}");
        };
        assert_eq!(report.total, 2);
        assert_eq!(report.delivered, 2);
        // Members first, confirmed root last.
        assert_eq!(ops.delivered_pids(), vec![150, 100]);
        // Terminate mode: every member is continued after its pending SIGTERM.
        assert!(ops.events.contains(&Event::Cont(150)));
        assert!(ops.events.contains(&Event::Cont(100)));
    }

    #[test]
    fn group_terminate_queues_every_term_before_any_continue() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            ginfo(100, Some(1), "root", 10, 42),
            ginfo(150, Some(100), "parent-like", 11, 42),
            ginfo(151, Some(150), "child-like", 12, 42),
        ];
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot.clone(), snapshot]);

        let outcome = execute_group_kill(
            &root,
            42,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completion, got {outcome:?}");
        };
        assert_eq!(report.total, 3);
        assert_eq!(ops.delivered_pids(), vec![150, 151, 100]);

        let first_continue = ops
            .events
            .iter()
            .position(|event| matches!(event, Event::Cont(_)))
            .expect("terminate mode must continue stopped members");
        let last_delivery = ops
            .events
            .iter()
            .rposition(|event| matches!(event, Event::Deliver(_, KillMode::Terminate)))
            .expect("terminate mode must deliver SIGTERM");
        assert!(
            last_delivery < first_continue,
            "group members must not resume until every SIGTERM is queued: {:?}",
            ops.events,
        );
    }

    #[test]
    fn group_final_verification_reuses_the_convergence_snapshot() {
        let root = root_target(100, "root", 10);
        let base = vec![ginfo(100, Some(1), "root", 10, 42)];
        let grown = vec![
            ginfo(100, Some(1), "root", 10, 42),
            ginfo(150, Some(100), "late", 11, 42),
        ];
        let mut ops = FakeOps::new(vec![
            base.clone(), // verify root
            base,         // sweep pass 1: nothing new yet
            grown,
        ]);
        ops.fresh_evidence.insert(
            100,
            Ok(FreshProcessEvidence {
                pid: 100,
                start_marker: crate::observation::ProcessStartMarker::linux(10)
                    .expect("test marker is valid"),
                name: "root".to_owned(),
            }),
        );

        let outcome = execute_group_kill(
            &root,
            42,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completion, got {outcome:?}");
        };
        assert_eq!(report.total, 1);
        assert_eq!(ops.delivered_pids(), vec![100]);
        assert_eq!(
            ops.next, 2,
            "no later snapshot may replace convergence evidence"
        );
    }

    #[test]
    fn group_member_reparenting_mid_kill_is_not_identity_drift() {
        let root = root_target(100, "root", 10);
        let before = vec![
            ginfo(100, Some(1), "root", 10, 42),
            // Its parent (250, outside the group) is alive at sweep time...
            ginfo(150, Some(250), "worker", 11, 42),
        ];
        // ...and exits before the final verify: the worker reparents, keeping
        // its group. Group identity is the group, not the parent — this must
        // proceed where the tree rules would refuse.
        let reparented = vec![
            ginfo(100, Some(1), "root", 10, 42),
            ginfo(150, Some(1), "worker", 11, 42),
        ];
        let mut ops = FakeOps::new(vec![
            before.clone(), // verify root
            before.clone(), // sweep pass 1: discovers 150
            reparented,     // sweep pass 2: converged after reparenting
        ]);

        let outcome = execute_group_kill(
            &root,
            42,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completion, got {outcome:?}");
        };
        assert_eq!(report.total, 2);
        assert_eq!(ops.delivered_pids(), vec![150, 100]);
    }

    #[test]
    fn group_member_leaving_the_group_post_stop_thaws_everything() {
        let root = root_target(100, "root", 10);
        let before = vec![
            ginfo(100, Some(1), "root", 10, 42),
            ginfo(150, Some(1), "worker", 11, 42),
        ];
        // The worker's group changed under the freeze (a setpgid from outside):
        // membership no longer provable, so the whole kill refuses and thaws.
        let moved = vec![
            ginfo(100, Some(1), "root", 10, 42),
            ginfo(150, Some(1), "worker", 11, 77),
        ];
        let mut ops = FakeOps::new(vec![before.clone(), before, moved]);

        let outcome = execute_group_kill(
            &root,
            42,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::TargetChanged { pid: 150 });
        assert!(ops.delivered_pids().is_empty());
        assert!(ops.events.ends_with(&[Event::Cont(150), Event::Cont(100)]));
    }

    #[test]
    fn group_root_that_moved_groups_thaws_and_refuses() {
        let root = root_target(100, "root", 10);
        // The user confirmed group 42, but by freeze time the root sits in 77:
        // sweeping 77 would kill a set the user never saw.
        let snapshot = vec![ginfo(100, Some(1), "root", 10, 77)];
        let mut ops = FakeOps::new(vec![snapshot]);

        let outcome = execute_group_kill(
            &root,
            42,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::TargetChanged { pid: 100 });
        assert_eq!(ops.events, vec![Event::Stop(100), Event::Cont(100)]);
    }

    #[test]
    fn group_cap_exceeded_during_freeze_thaws_and_refuses() {
        let root = root_target(100, "root", 10);
        let mut snapshot = vec![ginfo(100, Some(1), "root", 10, 42)];
        let over_cap = u32::try_from(MAX_GROUP_PROCESSES).unwrap() + 5;
        for pid in 1000..(1000 + over_cap) {
            snapshot.push(ginfo(pid, Some(1), "member", u64::from(pid), 42));
        }
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);

        let outcome = execute_group_kill(
            &root,
            42,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(
            outcome,
            TreeKillOutcome::Truncated {
                limit: MAX_GROUP_PROCESSES,
            },
        );
        assert!(ops.delivered_pids().is_empty());
        // Everything stopped so far was thawed — the same PIDs, not just the
        // same number of signals.
        let mut stopped: Vec<u32> = ops
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Stop(pid) => Some(*pid),
                _ => None,
            })
            .collect();
        let mut continued: Vec<u32> = ops
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Cont(pid) => Some(*pid),
                _ => None,
            })
            .collect();
        stopped.sort_unstable();
        continued.sort_unstable();
        assert_eq!(stopped, continued);
    }

    #[test]
    fn protected_group_member_thaws_and_refuses() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            ginfo(100, Some(1), "root", 10, 42),
            ginfo(150, Some(1), "postgres", 11, 42),
        ];
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot.clone(), snapshot]);

        let outcome = execute_group_kill(
            &root,
            42,
            KillMode::Terminate,
            &["postgres".to_owned()],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(
            outcome,
            TreeKillOutcome::ProtectedDescendant {
                pid: 150,
                name: Some("postgres".to_owned()),
            },
        );
        assert!(ops.delivered_pids().is_empty());
        assert!(ops.events.ends_with(&[Event::Cont(150), Event::Cont(100)]));
    }

    #[test]
    fn kickoutchi_inside_the_target_group_refuses_before_it_is_stopped() {
        // The script case: `server & kick kill --pid $! --group` in a plain
        // `sh -c` script puts kick itself in the target group. The sweep must
        // refuse on kick's own PID, never stop it.
        let root = root_target(100, "root", 10);
        let self_pid = std::process::id();
        let snapshot = vec![
            ginfo(100, Some(1), "root", 10, 42),
            ginfo(self_pid, Some(1), "kickoutchi", 11, 42),
        ];
        let mut ops = FakeOps::new(vec![snapshot.clone(), snapshot]);

        let outcome = execute_group_kill(
            &root,
            42,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert!(matches!(outcome, TreeKillOutcome::UnsafePid { pid, .. } if pid == self_pid));
        assert!(!ops.events.contains(&Event::Stop(self_pid)));
        assert!(ops.events.contains(&Event::Cont(100)));
    }

    /// A static parent chain deeper than the pass limit must freeze in a single
    /// snapshot pass: every generation is already visible in that snapshot, so
    /// depth must never consume passes. Guards against the sweep advancing only
    /// one generation per snapshot and refusing legitimate deep trees.
    #[test]
    fn deep_static_chain_freezes_in_one_pass_and_kills_leaves_first() {
        let root = root_target(100, "link", 10);
        // A 10-process chain: 100 -> 101 -> ... -> 109.
        let chain: Vec<TreeProcessInfo> = (0..10_u32)
            .map(|index| {
                let pid = 100 + index;
                let parent = if index == 0 { 1 } else { pid - 1 };
                info(pid, Some(parent), "link", 10 + u64::from(index))
            })
            .collect();
        // One static snapshot serves root verification, both sweep passes, and
        // fresh delivery evidence because the fake repeats its last snapshot.
        let mut ops = FakeOps::new(vec![chain]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completion, got {outcome:?}");
        };
        assert_eq!(report.total, 10);
        assert_eq!(report.delivered, 10);
        // Deepest first, root last.
        let expected: Vec<u32> = (100..110).rev().collect();
        assert_eq!(ops.delivered_pids(), expected);
    }

    /// Only a member set that keeps growing across fresh snapshots may exhaust
    /// the pass limit; the refusal must thaw exactly the PIDs it stopped.
    #[test]
    fn sweep_pass_limit_refuses_a_set_that_grows_every_snapshot_and_thaws_all() {
        let root = root_target(100, "root", 10);
        let base = vec![info(100, Some(1), "root", 10)];
        // Snapshot for pass k shows k children of the root: every fresh read
        // discovers one process the previous pass could not have seen.
        let mut snapshots = vec![base.clone()];
        for pass in 1..=8_u32 {
            let mut grown = base.clone();
            for child in 0..pass {
                let pid = 200 + child;
                grown.push(info(pid, Some(100), "spawned", u64::from(pid)));
            }
            snapshots.push(grown);
        }
        let mut ops = FakeOps::new(snapshots);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::SweepPassLimit { limit: 8 });
        assert!(ops.delivered_pids().is_empty());
        let mut stopped: Vec<u32> = ops
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Stop(pid) => Some(*pid),
                _ => None,
            })
            .collect();
        let mut continued: Vec<u32> = ops
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Cont(pid) => Some(*pid),
                _ => None,
            })
            .collect();
        stopped.sort_unstable();
        continued.sort_unstable();
        assert_eq!(stopped, continued, "every stopped PID must be thawed");
    }

    /// Post-stop verification must reject a frozen tree member whose parent
    /// PID changed, not only one whose start marker changed: the parent link
    /// is what proved tree membership.
    #[test]
    fn frozen_tree_member_reparenting_thaws_everything_and_refuses() {
        let root = root_target(100, "root", 10);
        let stable = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(100), "child", 11),
        ];
        // Same marker, different parent: membership is no longer provable.
        let reparented = vec![
            info(100, Some(1), "root", 10),
            info(101, Some(1), "child", 11),
        ];
        let mut ops = FakeOps::new(vec![
            stable.clone(), // verify root
            stable,         // sweep pass 1: discovers and freezes 101
            reparented,     // sweep pass 2: converged and verifies relation
        ]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::TargetChanged { pid: 101 });
        assert!(ops.delivered_pids().is_empty());
        assert!(ops.events.ends_with(&[Event::Cont(101), Event::Cont(100)]));
    }

    /// The confirmed root's parent is outside the frozen set, so it can exit and
    /// reparent the root without changing the root's identity or tree scope.
    #[test]
    fn frozen_tree_root_reparenting_is_not_identity_drift() {
        let root = root_target(100, "root", 10);
        let before = vec![info(100, Some(250), "root", 10)];
        let reparented = vec![info(100, Some(1), "root", 10)];
        let mut ops = FakeOps::new(vec![
            before,     // verify root
            reparented, // converged with only the root's parent changed
        ]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        let TreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completion, got {outcome:?}");
        };
        assert_eq!(report.total, 1);
        assert_eq!(ops.delivered_pids(), vec![100]);
    }

    /// A root confirmed without a readable name can `exec` into a protected
    /// name while keeping its PID, parent, and start marker. The final
    /// frozen-set policy must refuse it unless the protected-root typed
    /// confirmation was actually completed.
    #[test]
    fn root_exec_into_protected_name_refuses_without_protected_confirmation() {
        let mut confirmed = root_target(100, "postgres", 10);
        confirmed.process_name = None;
        let snapshot = vec![info(100, Some(500), "postgres", 10)];
        let protected = vec!["postgres".to_owned()];

        let mut ops = FakeOps::new(vec![snapshot.clone()]);
        let outcome = execute_tree_kill(
            &confirmed,
            KillMode::Terminate,
            &protected,
            Platform::Linux,
            auth(),
            &mut ops,
        );
        assert_eq!(
            outcome,
            TreeKillOutcome::ProtectedRoot {
                pid: 100,
                name: Some("postgres".to_owned()),
            },
        );
        assert!(ops.delivered_pids().is_empty());
        assert!(ops.events.ends_with(&[Event::Cont(100)]));

        // The same tree proceeds once the protected-root confirmation is real.
        let mut ops = FakeOps::new(vec![snapshot]);
        let outcome = execute_tree_kill(
            &confirmed,
            KillMode::Terminate,
            &protected,
            Platform::Linux,
            ScopeAuthorization {
                protected_root_confirmed: true,
                prompt_skipped: false,
            },
            &mut ops,
        );
        assert!(matches!(outcome, TreeKillOutcome::Completed(_)));
    }

    /// A skipped `--yes` prompt was justified by an all-clear preview; a
    /// system/service member appearing in the frozen set afterwards must void
    /// the skip and refuse, thawing everything.
    #[test]
    fn yes_skip_refuses_when_a_system_member_appears_mid_freeze() {
        let root = root_target(100, "root", 10);
        let base = vec![info(100, Some(500), "root", 10)];
        let grown = vec![
            info(100, Some(500), "root", 10),
            info(101, Some(100), "systemd", 11),
        ];
        let skipped = ScopeAuthorization {
            protected_root_confirmed: false,
            prompt_skipped: true,
        };
        let mut ops = FakeOps::new(vec![base, grown]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            skipped,
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::FreshConfirmationRequired);
        assert!(ops.delivered_pids().is_empty());
        assert!(ops.events.ends_with(&[Event::Cont(101), Event::Cont(100)]));
    }

    /// A skipped `--yes` prompt is also voided if a different-uid member appears
    /// after the all-clear preview. The final frozen set is authoritative for
    /// the same warning gates the preview used.
    #[test]
    fn yes_skip_refuses_when_an_owner_mismatch_appears_mid_freeze() {
        let root = root_target(100, "root", 10);
        let base = vec![info(100, Some(500), "root", 10)];
        let grown = vec![
            info(100, Some(500), "root", 10),
            TreeProcessInfo {
                owner_uid: Some(crate::process::current_user_id().saturating_add(1)),
                ..info(101, Some(100), "worker", 11)
            },
        ];
        let skipped = ScopeAuthorization {
            protected_root_confirmed: false,
            prompt_skipped: true,
        };
        let mut ops = FakeOps::new(vec![base, grown]);

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            skipped,
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::FreshConfirmationRequired);
        assert!(ops.delivered_pids().is_empty());
        assert!(ops.events.ends_with(&[Event::Cont(101), Event::Cont(100)]));
    }

    /// A group that outgrows [`GROUP_YES_SKIP_MAX_PROCESSES`] between the
    /// `--yes` skip and the end of the freeze no longer matches what the skip
    /// authorized: refuse, thaw, and ask for a prompted rerun.
    #[test]
    fn yes_skip_refuses_when_the_group_outgrows_the_skip_cap_mid_freeze() {
        let root = root_target(100, "root", 10);
        // Parent 500 keeps every member out of the system-process policy, so
        // this test isolates the size gate rather than the warning gate.
        let small = vec![
            ginfo(100, Some(500), "root", 10, 42),
            ginfo(150, Some(500), "worker", 11, 42),
        ];
        let mut grown = small.clone();
        for pid in 200..(200 + u32::try_from(GROUP_YES_SKIP_MAX_PROCESSES).expect("cap fits u32")) {
            grown.push(ginfo(pid, Some(500), "joiner", u64::from(pid), 42));
        }
        assert!(grown.len() > GROUP_YES_SKIP_MAX_PROCESSES);
        let skipped = ScopeAuthorization {
            protected_root_confirmed: false,
            prompt_skipped: true,
        };
        let mut ops = FakeOps::new(vec![small, grown]);

        let outcome = execute_group_kill(
            &root,
            42,
            KillMode::Terminate,
            &[],
            Platform::Linux,
            skipped,
            &mut ops,
        );

        assert_eq!(outcome, TreeKillOutcome::FreshConfirmationRequired);
        assert!(ops.delivered_pids().is_empty());
        let stops = ops
            .events
            .iter()
            .filter(|event| matches!(event, Event::Stop(_)))
            .count();
        let conts = ops
            .events
            .iter()
            .filter(|event| matches!(event, Event::Cont(_)))
            .count();
        assert_eq!(stops, conts, "every stopped member must be thawed");
    }

    #[test]
    fn final_evidence_missing_denied_oversized_and_identity_changed_deliver_nothing() {
        let cases = [
            (
                ProcessEvidenceError::Missing { pid: 100 },
                TreeKillOutcome::TargetChanged { pid: 100 },
            ),
            (
                ProcessEvidenceError::PermissionDenied { pid: 100 },
                TreeKillOutcome::PermissionDenied { pid: 100 },
            ),
            (
                ProcessEvidenceError::NameOversized {
                    pid: 100,
                    bytes: crate::observation::PROTECTION_NAME_MAX_BYTES + 1,
                },
                TreeKillOutcome::PartialMetadata { pid: 100 },
            ),
            (
                ProcessEvidenceError::IdentityChanged { pid: 100 },
                TreeKillOutcome::TargetChanged { pid: 100 },
            ),
        ];
        for (error, expected_outcome) in cases {
            let root = root_target(100, "root", 10);
            let snapshot = vec![info(100, Some(500), "root", 10)];
            let mut ops = FakeOps::new(vec![snapshot]);
            ops.fresh_evidence.insert(100, Err(error));

            let outcome = execute_tree_kill(
                &root,
                KillMode::Terminate,
                &[],
                Platform::Linux,
                auth(),
                &mut ops,
            );

            assert_eq!(outcome, expected_outcome);
            assert!(ops.delivered_pids().is_empty());
            assert_eq!(
                ops.events
                    .iter()
                    .filter(|event| matches!(event, Event::Stop(_)))
                    .count(),
                ops.events
                    .iter()
                    .filter(|event| matches!(event, Event::Cont(_)))
                    .count(),
            );
        }
    }

    #[test]
    fn newly_protected_final_evidence_refuses_before_any_delivery() {
        let root = root_target(100, "root", 10);
        let snapshot = vec![
            info(100, Some(500), "root", 10),
            info(101, Some(100), "worker", 11),
        ];
        let mut ops = FakeOps::new(vec![snapshot]);
        ops.fresh_evidence.insert(
            101,
            Ok(FreshProcessEvidence {
                pid: 101,
                start_marker: crate::observation::ProcessStartMarker::linux(11)
                    .expect("nonzero marker"),
                name: "postgres".to_owned(),
            }),
        );

        let outcome = execute_tree_kill(
            &root,
            KillMode::Terminate,
            &["postgres".to_owned()],
            Platform::Linux,
            auth(),
            &mut ops,
        );

        assert_eq!(
            outcome,
            TreeKillOutcome::ProtectedDescendant {
                pid: 101,
                name: Some("postgres".to_owned()),
            }
        );
        assert!(ops.delivered_pids().is_empty());
        assert!(
            !ops.events
                .iter()
                .any(|event| matches!(event, Event::Deliver(_, _)))
        );
    }
}
