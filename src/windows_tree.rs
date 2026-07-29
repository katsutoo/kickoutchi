//! Windows process-tree termination through Job Object containment.
//!
//! This is deliberately separate from the Unix freeze-first tree executor. Windows
//! has no supported SIGSTOP-equivalent safety primitive, so the safety boundary is
//! different: verify process handles first, begin containment by assigning the
//! root, converge on descendants, freeze, then re-prove final membership before
//! explicitly terminating the job. Assignment starts side effects; it is not an
//! atomic tree-termination commit.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::Instant;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JobObjectBasicProcessIdList, JobObjectReserved1Information, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, QueryFullProcessImageNameW, WaitForSingleObject,
};

use crate::model::Platform;
use crate::observation::{ProcessIdentity, ProcessStartMarker};
use crate::process::{KillTarget, UnsafePidReason, unsafe_pid_reason};
use crate::process_evidence::{
    ExpectedProcessEvidence, FreshProcessEvidence, ProcessEvidenceError, ProcessEvidenceScope,
};
use crate::protection::is_protected_process_name;
use crate::tree::{
    self, MAX_TREE_PROCESSES, PROCESS_TREE_INDEX_MAX, ProcessTreeIndex, ProcessTreeTarget,
    TreeKillOutcome, TreePlanError, TreeProcessInfo,
};

// Same finite convergence budget as the Unix freeze sweep. Windows containment
// is a different mechanism, but it still needs an explicit pass limit.
const WINDOWS_TREE_SWEEP_PASSES: usize = 8;
const WINDOWS_TREE_TERMINATE_EXIT_CODE: u32 = 1;
const WINDOWS_TREE_WAIT_MS: u32 = 5_000;
const WINDOWS_TREE_PROBE_WAIT_MS: u32 = 0;
const JOB_OBJECT_FREEZE_OPERATION: u32 = 1;
const JOB_MEMBERSHIP_QUERY_ATTEMPTS: usize = 8;
const PROCESS_IMAGE_PATH_CODE_UNITS_MAX: usize = 32 * 1024;

#[repr(C)]
struct JobObjectWakeFilter {
    high_edge_filter: u32,
    low_edge_filter: u32,
}

/// Private Windows class-18 payload used by `JobObjectReserved1Information`.
///
/// This 16-byte layout is not a stable public SDK contract. Production probes
/// freeze and thaw on an empty job before assigning the target, and every later
/// transition failure remains fail-closed with a best-effort thaw.
#[repr(C)]
struct JobObjectFreezeInformation {
    flags: u32,
    freeze: u8,
    swap: u8,
    reserved: [u8; 2],
    wake_filter: JobObjectWakeFilter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsTreeKillReport {
    pub(crate) total: usize,
    pub(crate) job_terminated_pids: Vec<u32>,
    pub(crate) already_exited_pids: Vec<u32>,
    pub(crate) not_terminated: Vec<u32>,
    pub(crate) termination_state: WindowsTreeTerminationState,
    pub(crate) post_commit_issue: Option<WindowsTreePostCommitIssue>,
    pub(crate) secondary_post_commit_issue: Option<WindowsTreePostCommitIssue>,
    pub(crate) cleanup_issue: Option<WindowsTreeCleanupIssue>,
}

/// Whether Job Object termination covered the proven tree.
///
/// One state replaces the former adjacent `containment_partial` and
/// `job_termination_withheld` booleans, making the unsafe contradictory state
/// "withheld but not partial" unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsTreeTerminationState {
    Complete,
    Partial,
    Withheld,
}

impl WindowsTreeTerminationState {
    fn mark_partial(&mut self) {
        if *self == Self::Complete {
            *self = Self::Partial;
        }
    }

    fn withhold(&mut self) {
        *self = Self::Withheld;
    }

    pub(crate) const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub(crate) const fn is_withheld(self) -> bool {
        matches!(self, Self::Withheld)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowsTreeCleanupIssue {
    WithheldJobThawFailed(String),
    FailedTerminationThawFailed(String),
    PostTerminationSurvivorsThawed {
        pids: Vec<u32>,
        wait_errors: Vec<(u32, String)>,
    },
    PostTerminationSurvivorThawFailed {
        pids: Vec<u32>,
        wait_errors: Vec<(u32, String)>,
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowsTreePostCommitIssue {
    RootAlreadyExited,
    PermissionDenied { pid: u32 },
    TargetChanged { pid: u32 },
    Truncated { limit: usize },
    SweepPassLimit { limit: usize },
    UnsafePid { pid: u32, reason: UnsafePidReason },
    ProtectedDescendant { pid: u32, name: Option<String> },
    ProtectedRoot { pid: u32, name: Option<String> },
    FreshConfirmationRequired,
    PartialMetadata { pid: u32 },
    SnapshotFailed(String),
}

impl WindowsTreePostCommitIssue {
    fn from_outcome(outcome: WindowsTreeKillOutcome) -> Option<Self> {
        match outcome {
            WindowsTreeKillOutcome::Completed(_)
            | WindowsTreeKillOutcome::OwnershipUnavailable { .. }
            | WindowsTreeKillOutcome::CommitFailed { .. }
            | WindowsTreeKillOutcome::FreezeCapabilityUnavailable { .. }
            | WindowsTreeKillOutcome::JobTerminateFailed { .. } => None,
            WindowsTreeKillOutcome::RootAlreadyExited => Some(Self::RootAlreadyExited),
            WindowsTreeKillOutcome::PermissionDenied { pid } => {
                Some(Self::PermissionDenied { pid })
            }
            WindowsTreeKillOutcome::TargetChanged { pid } => Some(Self::TargetChanged { pid }),
            WindowsTreeKillOutcome::Truncated { limit } => Some(Self::Truncated { limit }),
            WindowsTreeKillOutcome::SweepPassLimit { limit } => {
                Some(Self::SweepPassLimit { limit })
            }
            WindowsTreeKillOutcome::UnsafePid { pid, reason } => {
                Some(Self::UnsafePid { pid, reason })
            }
            WindowsTreeKillOutcome::ProtectedDescendant { pid, name } => {
                Some(Self::ProtectedDescendant { pid, name })
            }
            WindowsTreeKillOutcome::ProtectedRoot { pid, name } => {
                Some(Self::ProtectedRoot { pid, name })
            }
            WindowsTreeKillOutcome::FreshConfirmationRequired => {
                Some(Self::FreshConfirmationRequired)
            }
            WindowsTreeKillOutcome::PartialMetadata { pid } => Some(Self::PartialMetadata { pid }),
            WindowsTreeKillOutcome::SnapshotFailed(error) => Some(Self::SnapshotFailed(error)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowsTreeKillOutcome {
    Completed(Box<WindowsTreeKillReport>),
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
    CommitFailed {
        pid: u32,
        error: String,
    },
    FreezeCapabilityUnavailable {
        error: String,
    },
    JobTerminateFailed {
        error: String,
        report: Box<WindowsTreeKillReport>,
    },
}

impl WindowsTreeKillOutcome {
    pub(crate) fn from_precommit_outcome(outcome: TreeKillOutcome) -> Self {
        match outcome {
            TreeKillOutcome::RootAlreadyExited => Self::RootAlreadyExited,
            TreeKillOutcome::PermissionDenied { pid } => Self::PermissionDenied { pid },
            TreeKillOutcome::TargetChanged { pid } => Self::TargetChanged { pid },
            TreeKillOutcome::Truncated { limit } => Self::Truncated { limit },
            TreeKillOutcome::UnsafePid { pid, reason } => Self::UnsafePid { pid, reason },
            TreeKillOutcome::ProtectedDescendant { pid, name } => {
                Self::ProtectedDescendant { pid, name }
            }
            TreeKillOutcome::ProtectedRoot { pid, name } => Self::ProtectedRoot { pid, name },
            TreeKillOutcome::FreshConfirmationRequired => Self::FreshConfirmationRequired,
            TreeKillOutcome::OwnershipUnavailable { pid } => Self::OwnershipUnavailable { pid },
            TreeKillOutcome::PartialMetadata { pid } => Self::PartialMetadata { pid },
            TreeKillOutcome::SnapshotFailed(error) => Self::SnapshotFailed(error),
            TreeKillOutcome::ThawFailed { .. } => Self::SnapshotFailed(
                "unexpected Unix thaw outcome in Windows tree planning".to_owned(),
            ),
        }
    }
}

fn windows_plan_error(error: TreePlanError) -> WindowsTreeKillOutcome {
    match error {
        TreePlanError::RootMissing => WindowsTreeKillOutcome::RootAlreadyExited,
        TreePlanError::SnapshotLimitExceeded { limit } => {
            WindowsTreeKillOutcome::Truncated { limit }
        }
    }
}

pub(crate) fn execute_tree_kill(
    root: &KillTarget,
    protected_names: &[String],
    protected_root_confirmed: bool,
    prompt_skipped: bool,
) -> WindowsTreeKillOutcome {
    let mut api = RealWindowsTreeApi::new();
    execute_tree_kill_with(
        root,
        protected_names,
        protected_root_confirmed,
        prompt_skipped,
        &mut api,
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "the Windows commit boundary and post-commit handling stay visibly ordered"
)]
fn execute_tree_kill_with<Api: WindowsTreeApi>(
    root: &KillTarget,
    protected_names: &[String],
    protected_root_confirmed: bool,
    prompt_skipped: bool,
    api: &mut Api,
) -> WindowsTreeKillOutcome {
    if let Some(reason) = unsafe_pid_reason(root.pid) {
        return WindowsTreeKillOutcome::UnsafePid {
            pid: root.pid,
            reason,
        };
    }

    let snapshot = match api.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return WindowsTreeKillOutcome::SnapshotFailed(error),
    };
    let snapshot_index = match ProcessTreeIndex::new(&snapshot, PROCESS_TREE_INDEX_MAX) {
        Ok(index) => index,
        Err(TreePlanError::SnapshotLimitExceeded { limit }) => {
            return WindowsTreeKillOutcome::Truncated { limit };
        }
        Err(TreePlanError::RootMissing) => {
            unreachable!("index construction does not resolve roots")
        }
    };
    let (preview, confirmed_root_marker) = match build_precommit_preview(
        root,
        &snapshot,
        &snapshot_index,
        protected_names,
        protected_root_confirmed,
        prompt_skipped,
    ) {
        Ok(preview) => preview,
        Err(outcome) => return outcome,
    };

    let mut members = match pin_preview_members(
        api,
        &snapshot_index,
        &preview,
        root.pid,
        confirmed_root_marker,
    ) {
        Ok(members) => members,
        Err(outcome) => return outcome,
    };
    if let Err(outcome) = check_pinned_protection(
        &members,
        root.pid,
        protected_names,
        protected_root_confirmed,
    ) {
        return outcome;
    }
    if let Err(error) = api.preflight_job_freeze_thaw() {
        return WindowsTreeKillOutcome::FreezeCapabilityUnavailable { error };
    }
    let job = match api.create_job() {
        Ok(job) => job,
        Err(error) => return WindowsTreeKillOutcome::SnapshotFailed(error),
    };

    match commit_root_to_job(api, &job, root.pid, &mut members) {
        Ok(()) => {}
        Err(outcome) => return outcome,
    }

    let mut report = WindowsTreeKillReport {
        total: 0,
        job_terminated_pids: Vec::new(),
        already_exited_pids: Vec::new(),
        not_terminated: Vec::new(),
        termination_state: WindowsTreeTerminationState::Complete,
        post_commit_issue: None,
        secondary_post_commit_issue: None,
        cleanup_issue: None,
    };

    let mut assigned = HashSet::from([root.pid]);
    assign_initial_members(
        api,
        &job,
        root.pid,
        &mut members,
        &mut assigned,
        &mut report,
    );

    let mut sweep_passes_remaining = WINDOWS_TREE_SWEEP_PASSES;
    if let Err(outcome) = sweep_committed_tree(
        api,
        &job,
        root.pid,
        protected_names,
        prompt_skipped,
        &mut members,
        &mut assigned,
        &mut report,
        &mut sweep_passes_remaining,
    ) {
        record_post_commit_issue(&mut report, outcome);
    }

    let mut job_frozen = false;
    if !report.termination_state.is_withheld() {
        match api.set_job_frozen(&job, true) {
            Ok(()) => {
                job_frozen = true;
                if let Err(outcome) = sweep_committed_tree(
                    api,
                    &job,
                    root.pid,
                    protected_names,
                    prompt_skipped,
                    &mut members,
                    &mut assigned,
                    &mut report,
                    &mut sweep_passes_remaining,
                ) {
                    record_post_commit_issue(&mut report, outcome);
                }
            }
            Err(error) => {
                report.termination_state.withhold();
                record_post_commit_issue(
                    &mut report,
                    WindowsTreeKillOutcome::SnapshotFailed(format!(
                        "freezing committed Job Object failed: {error}"
                    )),
                );
                // Class 18 is private: an error does not prove the transition
                // had no partial effect. Make one bounded best-effort thaw.
                if let Err(thaw_error) = api.set_job_frozen(&job, false) {
                    record_cleanup_issue(
                        &mut report,
                        WindowsTreeCleanupIssue::WithheldJobThawFailed(thaw_error),
                    );
                }
            }
        }
    }

    if job_frozen
        && !report.termination_state.is_withheld()
        && let Err(outcome) = reconcile_final_containment(
            api,
            &job,
            root.pid,
            protected_names,
            protected_root_confirmed,
            prompt_skipped,
            &mut members,
            &mut assigned,
            &mut report,
        )
    {
        record_post_commit_issue(&mut report, outcome);
    }

    if report.termination_state.is_withheld() {
        if job_frozen && let Err(error) = api.set_job_frozen(&job, false) {
            record_cleanup_issue(
                &mut report,
                WindowsTreeCleanupIssue::WithheldJobThawFailed(error),
            );
        }
        finish_failed_job_report(&members, &assigned, &mut report);
        return WindowsTreeKillOutcome::Completed(Box::new(report));
    }

    if let Err(error) = api.terminate_job(&job) {
        if job_frozen && let Err(thaw_error) = api.set_job_frozen(&job, false) {
            record_cleanup_issue(
                &mut report,
                WindowsTreeCleanupIssue::FailedTerminationThawFailed(thaw_error),
            );
        }
        finish_failed_job_report(&members, &assigned, &mut report);
        return WindowsTreeKillOutcome::JobTerminateFailed {
            error,
            report: Box::new(report),
        };
    }

    finish_report(api, &job, &members, &mut report);
    WindowsTreeKillOutcome::Completed(Box::new(report))
}

/// The refusal for a protected process name found on `pid`: the root and a
/// descendant refuse through distinct outcomes so the caller can phrase the
/// re-confirmation prompt for the right process.
fn protected_outcome(pid: u32, root_pid: u32, name: &str) -> WindowsTreeKillOutcome {
    if pid == root_pid {
        WindowsTreeKillOutcome::ProtectedRoot {
            pid,
            name: Some(name.to_owned()),
        }
    } else {
        WindowsTreeKillOutcome::ProtectedDescendant {
            pid,
            name: Some(name.to_owned()),
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the final Windows containment proof keeps all refusal and cleanup state explicit"
)]
fn reconcile_final_containment<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    root_pid: u32,
    protected_names: &[String],
    protected_root_confirmed: bool,
    prompt_skipped: bool,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &mut HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) -> Result<(), WindowsTreeKillOutcome> {
    let exact_members = api.job_process_ids(job).map_err(job_membership_outcome)?;
    let exact_member_set = exact_members.iter().copied().collect::<HashSet<_>>();
    let snapshot = api
        .snapshot()
        .map_err(WindowsTreeKillOutcome::SnapshotFailed)?;
    if snapshot.len() > PROCESS_TREE_INDEX_MAX {
        return Err(WindowsTreeKillOutcome::Truncated {
            limit: PROCESS_TREE_INDEX_MAX,
        });
    }

    let snapshot_by_pid = snapshot_by_pid(&snapshot)?;
    let reachable = generation_qualified_descendants(&snapshot, &snapshot_by_pid, members)?;
    let mut final_pids = exact_member_set
        .union(&reachable)
        .copied()
        .collect::<Vec<_>>();
    if final_pids.len() > MAX_TREE_PROCESSES {
        return Err(WindowsTreeKillOutcome::Truncated {
            limit: MAX_TREE_PROCESSES,
        });
    }
    final_pids.sort_unstable();

    for pid in final_pids {
        let info = snapshot_by_pid
            .get(&pid)
            .copied()
            .ok_or(WindowsTreeKillOutcome::PartialMetadata { pid })?;
        if let Some(reason) = unsafe_pid_reason(pid) {
            return Err(WindowsTreeKillOutcome::UnsafePid { pid, reason });
        }
        let marker = info
            .start_time_marker
            .ok_or(WindowsTreeKillOutcome::PartialMetadata { pid })?;
        if members
            .get(&pid)
            .is_some_and(|process| process.start_marker != marker)
        {
            return Err(WindowsTreeKillOutcome::TargetChanged { pid });
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = members.entry(pid) {
            let process = open_verified_process(api, info, marker)
                .map_err(|error| open_error_outcome(pid, error))?;
            entry.insert(process);
        }
        let process = members
            .get_mut(&pid)
            .expect("the final member was retained or inserted above");
        if process.status == PinnedProcessStatus::AlreadyExited
            || api.process_start_marker(&process.handle) != Some(marker)
        {
            return Err(WindowsTreeKillOutcome::TargetChanged { pid });
        }
        let old_name = process.verified_name.clone();
        let fresh_name = api
            .process_name(&process.handle)
            .map_err(|error| windows_evidence_outcome(windows_api_evidence_error(pid, &error)))?
            .ok_or(WindowsTreeKillOutcome::PartialMetadata { pid })?;
        let mut evidence = ProcessEvidenceScope::new(1).map_err(windows_evidence_outcome)?;
        process.verified_name = evidence
            .observe(
                &ExpectedProcessEvidence {
                    pid,
                    start_marker: marker,
                    name: None,
                },
                Ok(FreshProcessEvidence {
                    pid,
                    start_marker: marker,
                    name: fresh_name,
                }),
            )
            .map_err(windows_evidence_outcome)?
            .name;
        evidence.finish().map_err(windows_evidence_outcome)?;
        let protected =
            is_protected_process_name(Platform::Windows, &process.verified_name, protected_names);
        if !old_name.is_empty() && old_name != process.verified_name {
            report.termination_state.withhold();
            if protected {
                return Err(protected_outcome(pid, root_pid, &process.verified_name));
            }
            return Err(WindowsTreeKillOutcome::TargetChanged { pid });
        }
        if protected && (pid != root_pid || !protected_root_confirmed) {
            report.termination_state.withhold();
            return Err(protected_outcome(pid, root_pid, &process.verified_name));
        }
        if prompt_skipped
            && (crate::model::SystemProcessCheck {
                platform: Platform::Windows,
                pid: Some(pid),
                parent_pid: info.parent_pid,
                process_name: Some(&process.verified_name),
                parent_process_name: info.parent_process_name.as_deref(),
            })
            .is_system_process()
        {
            report.termination_state.withhold();
            return Err(WindowsTreeKillOutcome::FreshConfirmationRequired);
        }
        if !exact_member_set.contains(&pid) {
            return Err(WindowsTreeKillOutcome::SnapshotFailed(format!(
                "live graph descendant PID {pid} was absent from exact frozen Job membership"
            )));
        }
        match api.process_in_job(job, &process.handle) {
            Ok(true) => {}
            Ok(false) => {
                return Err(WindowsTreeKillOutcome::SnapshotFailed(format!(
                    "exact frozen Job membership disagreed with the handle query for PID {pid}"
                )));
            }
            Err(error) => {
                return Err(WindowsTreeKillOutcome::SnapshotFailed(format!(
                    "reading frozen Job membership for PID {pid} failed: {}",
                    windows_api_error_text(&error)
                )));
            }
        }
        process.status = PinnedProcessStatus::AssignedToJob;
        assigned.insert(pid);
    }

    let mut historical_pids = members.keys().copied().collect::<Vec<_>>();
    historical_pids.sort_unstable();
    for pid in historical_pids {
        if exact_member_set.contains(&pid) {
            continue;
        }
        let process = members
            .get_mut(&pid)
            .expect("PID came from the same retained-member map");
        if process.status == PinnedProcessStatus::AlreadyExited {
            continue;
        }
        if matches!(
            api.wait_process_exit(&process.handle, WINDOWS_TREE_PROBE_WAIT_MS),
            WindowsWaitResult::Exited
        ) {
            process.status = PinnedProcessStatus::AlreadyExited;
            report.already_exited_pids.push(pid);
            assigned.remove(&pid);
        } else {
            return Err(WindowsTreeKillOutcome::SnapshotFailed(format!(
                "previously contained live PID {pid} was absent from exact frozen Job membership"
            )));
        }
    }

    let stable_members = api.job_process_ids(job).map_err(job_membership_outcome)?;
    if stable_members != exact_members {
        return Err(WindowsTreeKillOutcome::SnapshotFailed(
            "frozen Job Object membership changed during final reconciliation".to_owned(),
        ));
    }

    Ok(())
}

fn job_membership_outcome(error: JobMembershipError) -> WindowsTreeKillOutcome {
    match error {
        JobMembershipError::Oversized { limit } => WindowsTreeKillOutcome::Truncated { limit },
        JobMembershipError::Raced => WindowsTreeKillOutcome::SnapshotFailed(
            "frozen Job Object membership did not stabilize within the bounded query budget"
                .to_owned(),
        ),
        JobMembershipError::Unreadable(error) => WindowsTreeKillOutcome::SnapshotFailed(error),
    }
}

fn snapshot_by_pid(
    snapshot: &[TreeProcessInfo],
) -> Result<HashMap<u32, &TreeProcessInfo>, WindowsTreeKillOutcome> {
    let mut by_pid = HashMap::with_capacity(snapshot.len());
    for info in snapshot {
        if by_pid.insert(info.pid, info).is_some() {
            return Err(WindowsTreeKillOutcome::PartialMetadata { pid: info.pid });
        }
    }
    Ok(by_pid)
}

fn generation_qualified_descendants<Handle>(
    snapshot: &[TreeProcessInfo],
    snapshot_by_pid: &HashMap<u32, &TreeProcessInfo>,
    members: &HashMap<u32, PinnedProcess<Handle>>,
) -> Result<HashSet<u32>, WindowsTreeKillOutcome> {
    let mut children_by_parent: HashMap<u32, Vec<&TreeProcessInfo>> = HashMap::new();
    let mut unverified_by_parent: HashMap<u32, Vec<&TreeProcessInfo>> = HashMap::new();
    for info in snapshot {
        if let Some(parent_pid) = info.parent_pid {
            children_by_parent.entry(parent_pid).or_default().push(info);
        }
        if let Some(parent_pid) = info.unverified_parent_pid {
            unverified_by_parent
                .entry(parent_pid)
                .or_default()
                .push(info);
        }
    }

    let mut reachable = HashSet::new();
    let mut frontier = Vec::new();
    for (&pid, process) in members {
        if process.status == PinnedProcessStatus::AlreadyExited {
            continue;
        }
        if snapshot_by_pid
            .get(&pid)
            .and_then(|info| info.start_time_marker)
            == Some(process.start_marker)
        {
            reachable.insert(pid);
            frontier.push(ProcessIdentity {
                pid,
                start_marker: process.start_marker,
            });
        }
    }

    while let Some(parent) = frontier.pop() {
        if snapshot_by_pid
            .get(&parent.pid)
            .and_then(|info| info.start_time_marker)
            != Some(parent.start_marker)
        {
            continue;
        }
        if let Some(children) = unverified_by_parent.get(&parent.pid)
            && let Some(child) = children.first()
        {
            return Err(WindowsTreeKillOutcome::PartialMetadata { pid: child.pid });
        }
        for child in children_by_parent
            .get(&parent.pid)
            .map_or(&[][..], Vec::as_slice)
        {
            let marker = child
                .start_time_marker
                .ok_or(WindowsTreeKillOutcome::PartialMetadata { pid: child.pid })?;
            if members
                .get(&child.pid)
                .is_some_and(|process| process.start_marker != marker)
            {
                return Err(WindowsTreeKillOutcome::TargetChanged { pid: child.pid });
            }
            if reachable.insert(child.pid) {
                if reachable.len() > MAX_TREE_PROCESSES {
                    return Err(WindowsTreeKillOutcome::Truncated {
                        limit: MAX_TREE_PROCESSES,
                    });
                }
                frontier.push(ProcessIdentity {
                    pid: child.pid,
                    start_marker: marker,
                });
            }
        }
    }
    Ok(reachable)
}

fn build_precommit_preview(
    root: &KillTarget,
    snapshot: &[TreeProcessInfo],
    snapshot_index: &ProcessTreeIndex<'_>,
    protected_names: &[String],
    protected_root_confirmed: bool,
    prompt_skipped: bool,
) -> Result<(ProcessTreeTarget, ProcessStartMarker), WindowsTreeKillOutcome> {
    let confirmed_root_marker = verify_snapshot_root_identity(root, snapshot_index)?;
    let preview = tree::plan_process_tree_with_index(
        root.pid,
        snapshot_index,
        protected_names,
        Platform::Windows,
        MAX_TREE_PROCESSES,
    )
    .map_err(windows_plan_error)?;
    tree::preflight_outcome(&preview).map_err(WindowsTreeKillOutcome::from_precommit_outcome)?;
    tree::root_protection_outcome(&preview, protected_root_confirmed)
        .map_err(WindowsTreeKillOutcome::from_precommit_outcome)?;
    if prompt_skipped && preview.has_warnings() {
        return Err(WindowsTreeKillOutcome::FreshConfirmationRequired);
    }
    if let Some(pid) = first_partial_metadata_pid(snapshot, snapshot_index, &preview) {
        return Err(WindowsTreeKillOutcome::PartialMetadata { pid });
    }
    Ok((preview, confirmed_root_marker))
}

fn verify_snapshot_root_identity(
    root: &KillTarget,
    snapshot_index: &ProcessTreeIndex<'_>,
) -> Result<ProcessStartMarker, WindowsTreeKillOutcome> {
    let confirmed_marker = root
        .process_start_time_marker
        .ok_or(WindowsTreeKillOutcome::PartialMetadata { pid: root.pid })?;
    let info = snapshot_index
        .process(root.pid)
        .ok_or(WindowsTreeKillOutcome::RootAlreadyExited)?;
    match info.start_time_marker {
        Some(marker) if marker == confirmed_marker => {}
        Some(_) => return Err(WindowsTreeKillOutcome::TargetChanged { pid: root.pid }),
        None => return Err(WindowsTreeKillOutcome::PartialMetadata { pid: root.pid }),
    }
    if let Some(confirmed_name) = root.process_name.as_deref() {
        match info.process_name.as_deref() {
            Some(fresh_name) if fresh_name == confirmed_name => {}
            Some(_) => return Err(WindowsTreeKillOutcome::TargetChanged { pid: root.pid }),
            None => return Err(WindowsTreeKillOutcome::PartialMetadata { pid: root.pid }),
        }
    }
    Ok(confirmed_marker)
}

fn first_partial_metadata_pid(
    snapshot: &[TreeProcessInfo],
    snapshot_index: &ProcessTreeIndex<'_>,
    preview: &ProcessTreeTarget,
) -> Option<u32> {
    let preview_nodes = preview.preview_nodes(preview.len());
    let preview_pids = preview_nodes
        .iter()
        .map(|node| node.pid)
        .collect::<HashSet<_>>();
    for node in preview_nodes {
        let Some(info) = snapshot_index.process(node.pid) else {
            continue;
        };
        if info.process_name.is_none() || info.start_time_marker.is_none() {
            return Some(info.pid);
        }
    }

    let mut unverified_children = snapshot
        .iter()
        .filter(|info| !preview_pids.contains(&info.pid))
        .filter(|info| {
            info.unverified_parent_pid
                .is_some_and(|parent_pid| preview_pids.contains(&parent_pid))
        })
        .collect::<Vec<_>>();
    unverified_children.sort_by_key(|info| info.pid);
    unverified_children.first().map(|info| info.pid)
}

fn pin_preview_members<Api: WindowsTreeApi>(
    api: &mut Api,
    snapshot_index: &ProcessTreeIndex<'_>,
    preview: &ProcessTreeTarget,
    root_pid: u32,
    confirmed_root_marker: ProcessStartMarker,
) -> Result<HashMap<u32, PinnedProcess<Api::ProcessHandle>>, WindowsTreeKillOutcome> {
    let mut members = HashMap::new();
    for node in preview.preview_nodes(preview.len()) {
        let Some(info) = snapshot_index.process(node.pid) else {
            return Err(WindowsTreeKillOutcome::TargetChanged { pid: node.pid });
        };
        let expected_marker = if info.pid == root_pid {
            confirmed_root_marker
        } else {
            info.start_time_marker
                .ok_or(WindowsTreeKillOutcome::PartialMetadata { pid: info.pid })?
        };
        let process = open_verified_process(api, info, expected_marker)
            .map_err(|error| open_error_outcome(info.pid, error))?;
        members.insert(info.pid, process);
    }

    let mut evidence_scope =
        ProcessEvidenceScope::new(members.len()).map_err(windows_evidence_outcome)?;
    let mut pids = members.keys().copied().collect::<Vec<_>>();
    pids.sort_unstable();
    for pid in pids {
        let info = snapshot_index
            .process(pid)
            .ok_or(WindowsTreeKillOutcome::TargetChanged { pid })?;
        let expected_marker = if pid == root_pid {
            confirmed_root_marker
        } else {
            info.start_time_marker
                .ok_or(WindowsTreeKillOutcome::PartialMetadata { pid })?
        };
        let expected = ExpectedProcessEvidence {
            pid,
            start_marker: expected_marker,
            name: (pid == root_pid)
                .then_some(info.process_name.as_deref())
                .flatten(),
        };
        let process = members
            .get_mut(&pid)
            .expect("PID came from the same pinned-member map");
        let name = api
            .process_name(&process.handle)
            .map_err(|error| windows_evidence_outcome(windows_api_evidence_error(pid, &error)))?;
        let fresh = evidence_scope
            .observe(
                &expected,
                Ok(FreshProcessEvidence {
                    pid,
                    start_marker: expected_marker,
                    name: name.ok_or_else(|| {
                        windows_evidence_outcome(ProcessEvidenceError::NameMissing { pid })
                    })?,
                }),
            )
            .map_err(windows_evidence_outcome)?;
        process.verified_name = fresh.name;
    }
    evidence_scope.finish().map_err(windows_evidence_outcome)?;
    Ok(members)
}

fn check_pinned_protection<Handle>(
    members: &HashMap<u32, PinnedProcess<Handle>>,
    root_pid: u32,
    protected_names: &[String],
    protected_root_confirmed: bool,
) -> Result<(), WindowsTreeKillOutcome> {
    let mut pids = members.keys().copied().collect::<Vec<_>>();
    pids.sort_unstable();
    for pid in pids {
        let name = &members[&pid].verified_name;
        if !is_protected_process_name(Platform::Windows, name, protected_names) {
            continue;
        }
        if pid == root_pid {
            if !protected_root_confirmed {
                return Err(WindowsTreeKillOutcome::ProtectedRoot {
                    pid,
                    name: Some(name.clone()),
                });
            }
        } else {
            return Err(WindowsTreeKillOutcome::ProtectedDescendant {
                pid,
                name: Some(name.clone()),
            });
        }
    }
    Ok(())
}

fn windows_api_evidence_error(pid: u32, error: &WindowsApiError) -> ProcessEvidenceError {
    match error {
        WindowsApiError::PermissionDenied => ProcessEvidenceError::PermissionDenied { pid },
        WindowsApiError::NotFound | WindowsApiError::Other(_) => {
            ProcessEvidenceError::Missing { pid }
        }
    }
}

fn windows_api_error_text(error: &WindowsApiError) -> &str {
    match error {
        WindowsApiError::NotFound => "process was not found",
        WindowsApiError::PermissionDenied => "permission denied",
        WindowsApiError::Other(error) => error,
    }
}

fn windows_evidence_outcome(error: ProcessEvidenceError) -> WindowsTreeKillOutcome {
    match error {
        ProcessEvidenceError::PermissionDenied { pid } => {
            WindowsTreeKillOutcome::PermissionDenied { pid }
        }
        ProcessEvidenceError::IdentityChanged { pid }
        | ProcessEvidenceError::NameChanged { pid }
        | ProcessEvidenceError::Missing { pid } => WindowsTreeKillOutcome::TargetChanged { pid },
        ProcessEvidenceError::NameMissing { pid }
        | ProcessEvidenceError::NameOversized { pid, .. } => {
            WindowsTreeKillOutcome::PartialMetadata { pid }
        }
        ProcessEvidenceError::IncompleteScope { .. }
        | ProcessEvidenceError::MemberLimitExceeded { .. }
        | ProcessEvidenceError::ByteLimitExceeded { .. } => WindowsTreeKillOutcome::SnapshotFailed(
            "fresh process evidence exceeded its bounded scope".to_owned(),
        ),
    }
}

fn record_post_commit_issue(report: &mut WindowsTreeKillReport, outcome: WindowsTreeKillOutcome) {
    report.termination_state.mark_partial();
    // After root assignment, every sweep/evidence failure means the contained
    // membership is uncertain. Terminating the job could then kill an unknown
    // or newly protected process, so uncertainty always withholds it.
    if !matches!(outcome, WindowsTreeKillOutcome::ProtectedDescendant { .. }) {
        report.termination_state.withhold();
    }
    let Some(issue) = WindowsTreePostCommitIssue::from_outcome(outcome) else {
        return;
    };
    if report.post_commit_issue.is_none() {
        report.post_commit_issue = Some(issue);
    } else if report.secondary_post_commit_issue.is_none() {
        report.secondary_post_commit_issue = Some(issue);
    }
}

fn record_cleanup_issue(report: &mut WindowsTreeKillReport, issue: WindowsTreeCleanupIssue) {
    report.termination_state.mark_partial();
    if report.cleanup_issue.is_none() {
        report.cleanup_issue = Some(issue);
    }
}

fn commit_root_to_job<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    root_pid: u32,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
) -> Result<(), WindowsTreeKillOutcome> {
    let Some(root) = members.get_mut(&root_pid) else {
        return Err(WindowsTreeKillOutcome::RootAlreadyExited);
    };
    match api.assign_process(job, &root.handle) {
        Ok(()) => {
            root.status = PinnedProcessStatus::AssignedToJob;
            Ok(())
        }
        Err(WindowsApiError::NotFound) => Err(WindowsTreeKillOutcome::RootAlreadyExited),
        Err(WindowsApiError::PermissionDenied) => {
            Err(WindowsTreeKillOutcome::PermissionDenied { pid: root_pid })
        }
        Err(WindowsApiError::Other(error)) => Err(WindowsTreeKillOutcome::CommitFailed {
            pid: root_pid,
            error,
        }),
    }
}

fn assign_initial_members<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    root_pid: u32,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &mut HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) {
    let mut pids = members.keys().copied().collect::<Vec<_>>();
    pids.sort_unstable();
    for pid in pids {
        if pid == root_pid {
            continue;
        }
        assign_or_withhold(api, job, pid, members, assigned, report);
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the post-commit convergence keeps all safety-critical state and ordering explicit"
)]
fn sweep_committed_tree<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    root_pid: u32,
    protected_names: &[String],
    prompt_skipped: bool,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &mut HashSet<u32>,
    report: &mut WindowsTreeKillReport,
    sweep_passes_remaining: &mut usize,
) -> Result<(), WindowsTreeKillOutcome> {
    let mut consecutive_clean_passes = 0usize;
    while *sweep_passes_remaining > 0 {
        *sweep_passes_remaining -= 1;
        let snapshot = api
            .snapshot()
            .map_err(WindowsTreeKillOutcome::SnapshotFailed)?;
        let snapshot_by_pid = snapshot_by_pid(&snapshot)?;
        for (&pid, process) in &*members {
            if snapshot_by_pid
                .get(&pid)
                .and_then(|info| info.start_time_marker)
                .is_some_and(|marker| marker != process.start_marker)
            {
                return Err(WindowsTreeKillOutcome::TargetChanged { pid });
            }
        }
        let snapshot_index =
            ProcessTreeIndex::new(&snapshot, PROCESS_TREE_INDEX_MAX).map_err(windows_plan_error)?;
        let preview = tree::plan_process_tree_with_index(
            root_pid,
            &snapshot_index,
            protected_names,
            Platform::Windows,
            MAX_TREE_PROCESSES,
        )
        .map_err(windows_plan_error)?;
        if preview.truncated() {
            return Err(WindowsTreeKillOutcome::Truncated {
                limit: MAX_TREE_PROCESSES,
            });
        }
        if prompt_skipped && preview.has_warnings() {
            return Err(WindowsTreeKillOutcome::FreshConfirmationRequired);
        }
        if let Some(pid) = first_partial_metadata_pid(&snapshot, &snapshot_index, &preview) {
            return Err(WindowsTreeKillOutcome::PartialMetadata { pid });
        }

        let mut discovered = false;
        for node in preview.preview_nodes(preview.len()) {
            if members.contains_key(&node.pid) {
                continue;
            }
            if members.len() >= MAX_TREE_PROCESSES {
                return Err(WindowsTreeKillOutcome::Truncated {
                    limit: MAX_TREE_PROCESSES,
                });
            }
            let Some(info) = snapshot_index.process(node.pid) else {
                continue;
            };
            if let Some(reason) = unsafe_pid_reason(node.pid) {
                report.not_terminated.push(node.pid);
                return Err(WindowsTreeKillOutcome::UnsafePid {
                    pid: node.pid,
                    reason,
                });
            }
            let Some(expected_marker) = info.start_time_marker else {
                report.not_terminated.push(info.pid);
                return Err(WindowsTreeKillOutcome::PartialMetadata { pid: info.pid });
            };
            let mut process = match open_verified_process(api, info, expected_marker) {
                Ok(process) => process,
                Err(OpenVerifiedError::NotFound) => {
                    report.already_exited_pids.push(info.pid);
                    continue;
                }
                // Any other open failure aborts the sweep: record the PID as
                // not terminated and map the error exactly as the pinning
                // paths do, so the user-facing outcome matches
                // `pin_preview_members` for the same failure.
                Err(error) => {
                    report.not_terminated.push(info.pid);
                    return Err(open_error_outcome(info.pid, error));
                }
            };
            let expected = ExpectedProcessEvidence {
                pid: info.pid,
                start_marker: expected_marker,
                name: None,
            };
            let mut evidence_scope =
                ProcessEvidenceScope::new(1).map_err(windows_evidence_outcome)?;
            let name = match api.process_name(&process.handle) {
                Ok(Some(name)) => name,
                Ok(None) => {
                    return Err(handle_unknown_post_commit_child(
                        api,
                        job,
                        info.pid,
                        process,
                        ProcessEvidenceError::NameMissing { pid: info.pid },
                        members,
                        assigned,
                        report,
                    ));
                }
                Err(error) => {
                    let evidence_error = windows_api_evidence_error(info.pid, &error);
                    return Err(handle_unknown_post_commit_child(
                        api,
                        job,
                        info.pid,
                        process,
                        evidence_error,
                        members,
                        assigned,
                        report,
                    ));
                }
            };
            let fresh = match evidence_scope.observe(
                &expected,
                Ok(FreshProcessEvidence {
                    pid: info.pid,
                    start_marker: expected_marker,
                    name,
                }),
            ) {
                Ok(fresh) => fresh,
                Err(error) => {
                    return Err(handle_unknown_post_commit_child(
                        api, job, info.pid, process, error, members, assigned, report,
                    ));
                }
            };
            process.verified_name = fresh.name;
            if is_protected_process_name(Platform::Windows, &process.verified_name, protected_names)
            {
                return Err(handle_protected_post_commit_child(
                    api, job, info.pid, process, members, assigned, report,
                ));
            }
            members.insert(info.pid, process);
            assign_or_withhold(api, job, info.pid, members, assigned, report);
            discovered = true;
        }
        if discovered {
            consecutive_clean_passes = 0;
        } else {
            consecutive_clean_passes += 1;
            // One extra final-window snapshot catches a child appearing after
            // the first apparently stable sweep and before job termination.
            if consecutive_clean_passes == 2 {
                return Ok(());
            }
        }
    }
    Err(WindowsTreeKillOutcome::SweepPassLimit {
        limit: WINDOWS_TREE_SWEEP_PASSES,
    })
}

fn handle_protected_post_commit_child<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    pid: u32,
    mut process: PinnedProcess<Api::ProcessHandle>,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &mut HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) -> WindowsTreeKillOutcome {
    let name = process.verified_name.clone();
    match api.process_in_job(job, &process.handle) {
        Ok(true) => {
            process.status = PinnedProcessStatus::AssignedToJob;
            assigned.insert(pid);
            members.insert(pid, process);
            report.termination_state.withhold();
            report.not_terminated.push(pid);
        }
        Ok(false) => report.not_terminated.push(pid),
        Err(_) => {
            // An unknown containment state may mean the protected process is
            // already in the job. Terminating either the job or this handle
            // would therefore be unsafe.
            report.termination_state.withhold();
            report.not_terminated.push(pid);
        }
    }
    WindowsTreeKillOutcome::ProtectedDescendant {
        pid,
        name: Some(name),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "post-commit refusal keeps the job, pinned child, evidence, and report explicit"
)]
fn handle_unknown_post_commit_child<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    pid: u32,
    mut process: PinnedProcess<Api::ProcessHandle>,
    error: ProcessEvidenceError,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &mut HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) -> WindowsTreeKillOutcome {
    match api.process_in_job(job, &process.handle) {
        Ok(true) => {
            process.status = PinnedProcessStatus::AssignedToJob;
            assigned.insert(pid);
            members.insert(pid, process);
            report.termination_state.withhold();
        }
        Ok(false) => {}
        Err(_) => report.termination_state.withhold(),
    }
    report.not_terminated.push(pid);
    windows_evidence_outcome(error)
}

fn assign_or_withhold<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    pid: u32,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &mut HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) {
    let Some(process) = members.get_mut(&pid) else {
        return;
    };
    if let Ok(true) = api.process_in_job(job, &process.handle) {
        process.status = PinnedProcessStatus::AssignedToJob;
        assigned.insert(pid);
        return;
    }

    match api.assign_process(job, &process.handle) {
        Ok(()) => {
            process.status = PinnedProcessStatus::AssignedToJob;
            assigned.insert(pid);
        }
        Err(WindowsApiError::NotFound) => {
            process.status = PinnedProcessStatus::AlreadyExited;
            report.already_exited_pids.push(pid);
        }
        Err(WindowsApiError::PermissionDenied | WindowsApiError::Other(_)) => {
            if matches!(
                api.wait_process_exit(&process.handle, WINDOWS_TREE_PROBE_WAIT_MS),
                WindowsWaitResult::Exited
            ) {
                process.status = PinnedProcessStatus::AlreadyExited;
                report.already_exited_pids.push(pid);
                return;
            }
            report.termination_state.withhold();
        }
    }
}

fn finish_report<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    members: &HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    report: &mut WindowsTreeKillReport,
) {
    report.job_terminated_pids.clear();
    let deadline_ms = api.now_ms().saturating_add(u64::from(WINDOWS_TREE_WAIT_MS));
    let mut wait_errors = Vec::new();
    let mut pids = members.keys().copied().collect::<Vec<_>>();
    pids.sort_unstable();
    for pid in pids {
        let process = &members[&pid];
        if process.status == PinnedProcessStatus::AlreadyExited {
            continue;
        }
        if process.status == PinnedProcessStatus::AssignedToJob {
            let remaining_ms = deadline_ms.saturating_sub(api.now_ms());
            let timeout_ms = u32::try_from(remaining_ms).unwrap_or(u32::MAX);
            match api.wait_process_exit(&process.handle, timeout_ms) {
                WindowsWaitResult::Exited => report.job_terminated_pids.push(pid),
                WindowsWaitResult::StillRunning => {
                    if !report.not_terminated.contains(&pid) {
                        report.not_terminated.push(pid);
                    }
                }
                WindowsWaitResult::Failed(error) => {
                    wait_errors.push((pid, error));
                    if !report.not_terminated.contains(&pid) {
                        report.not_terminated.push(pid);
                    }
                }
            }
        }
    }
    if !report.not_terminated.is_empty() {
        let pids = report.not_terminated.clone();
        let issue = match api.set_job_frozen(job, false) {
            Ok(()) => WindowsTreeCleanupIssue::PostTerminationSurvivorsThawed { pids, wait_errors },
            Err(error) => WindowsTreeCleanupIssue::PostTerminationSurvivorThawFailed {
                pids,
                wait_errors,
                error,
            },
        };
        record_cleanup_issue(report, issue);
    }
    normalize_report_pids(report);
    report.total = observed_process_count(members, report);
    if !report.not_terminated.is_empty() {
        report.termination_state.mark_partial();
    }
}

/// Finalize observable state when job termination is withheld or fails.
///
/// Assignment is the commit boundary, but assignment is not termination. Every
/// process assigned to the job therefore remains explicitly unconfirmed. A live
/// member that could not join the job remains unconfirmed as well; terminating
/// it individually would reopen the descendant-spawn window.
fn finish_failed_job_report<ProcessHandle>(
    members: &HashMap<u32, PinnedProcess<ProcessHandle>>,
    assigned: &HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) {
    report.job_terminated_pids.clear();
    report.not_terminated.extend(assigned.iter().copied());
    report
        .not_terminated
        .extend(members.iter().filter_map(|(pid, process)| {
            (process.status == PinnedProcessStatus::Pending).then_some(*pid)
        }));
    report.termination_state.mark_partial();
    normalize_report_pids(report);
    report.total = observed_process_count(members, report);
}

fn normalize_report_pids(report: &mut WindowsTreeKillReport) {
    for pids in [
        &mut report.job_terminated_pids,
        &mut report.already_exited_pids,
        &mut report.not_terminated,
    ] {
        pids.sort_unstable();
        pids.dedup();
    }
}

fn observed_process_count<ProcessHandle>(
    members: &HashMap<u32, PinnedProcess<ProcessHandle>>,
    report: &WindowsTreeKillReport,
) -> usize {
    let mut observed = members.keys().copied().collect::<HashSet<_>>();
    observed.extend(report.job_terminated_pids.iter().copied());
    observed.extend(report.already_exited_pids.iter().copied());
    observed.extend(report.not_terminated.iter().copied());
    observed.len()
}

fn open_verified_process<Api: WindowsTreeApi>(
    api: &mut Api,
    info: &TreeProcessInfo,
    expected_marker: ProcessStartMarker,
) -> Result<PinnedProcess<Api::ProcessHandle>, OpenVerifiedError> {
    if info.process_name.is_none() {
        return Err(OpenVerifiedError::PartialMetadata);
    }
    let handle = api.open_process(info.pid).map_err(|error| match error {
        WindowsApiError::NotFound => OpenVerifiedError::NotFound,
        WindowsApiError::PermissionDenied => OpenVerifiedError::PermissionDenied,
        WindowsApiError::Other(error) => OpenVerifiedError::Other(error),
    })?;
    match api.process_start_marker(&handle) {
        Some(marker) if marker == expected_marker => Ok(PinnedProcess {
            handle,
            start_marker: expected_marker,
            verified_name: String::new(),
            status: PinnedProcessStatus::Pending,
        }),
        Some(_) => Err(OpenVerifiedError::NotFound),
        None => Err(OpenVerifiedError::PartialMetadata),
    }
}

struct PinnedProcess<Handle> {
    handle: Handle,
    start_marker: ProcessStartMarker,
    verified_name: String,
    status: PinnedProcessStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinnedProcessStatus {
    Pending,
    AssignedToJob,
    AlreadyExited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenVerifiedError {
    NotFound,
    PermissionDenied,
    PartialMetadata,
    Other(String),
}

/// Map an [`open_verified_process`] failure on `pid` to the user-facing
/// outcome. Every open site shares this mapping so the same OS failure can
/// never surface as different outcomes depending on which phase observed it.
fn open_error_outcome(pid: u32, error: OpenVerifiedError) -> WindowsTreeKillOutcome {
    match error {
        OpenVerifiedError::NotFound => WindowsTreeKillOutcome::TargetChanged { pid },
        OpenVerifiedError::PermissionDenied => WindowsTreeKillOutcome::PermissionDenied { pid },
        OpenVerifiedError::PartialMetadata => WindowsTreeKillOutcome::PartialMetadata { pid },
        OpenVerifiedError::Other(error) => WindowsTreeKillOutcome::SnapshotFailed(error),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WindowsApiError {
    NotFound,
    PermissionDenied,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WindowsWaitResult {
    Exited,
    StillRunning,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JobMembershipError {
    Oversized { limit: usize },
    Raced,
    Unreadable(String),
}

trait WindowsTreeApi {
    type ProcessHandle;
    type JobHandle;

    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String>;
    fn open_process(&mut self, pid: u32) -> Result<Self::ProcessHandle, WindowsApiError>;
    fn process_start_marker(&mut self, handle: &Self::ProcessHandle) -> Option<ProcessStartMarker>;
    fn process_name(
        &mut self,
        handle: &Self::ProcessHandle,
    ) -> Result<Option<String>, WindowsApiError>;
    fn preflight_job_freeze_thaw(&mut self) -> Result<(), String>;
    fn create_job(&mut self) -> Result<Self::JobHandle, String>;
    fn process_in_job(
        &mut self,
        job: &Self::JobHandle,
        process: &Self::ProcessHandle,
    ) -> Result<bool, WindowsApiError>;
    fn assign_process(
        &mut self,
        job: &Self::JobHandle,
        process: &Self::ProcessHandle,
    ) -> Result<(), WindowsApiError>;
    fn set_job_frozen(&mut self, job: &Self::JobHandle, frozen: bool) -> Result<(), String>;
    fn job_process_ids(&mut self, job: &Self::JobHandle) -> Result<Vec<u32>, JobMembershipError>;
    fn terminate_job(&mut self, job: &Self::JobHandle) -> Result<(), String>;
    fn now_ms(&mut self) -> u64;
    fn wait_process_exit(
        &mut self,
        process: &Self::ProcessHandle,
        timeout_ms: u32,
    ) -> WindowsWaitResult;
}

struct RealWindowsTreeApi {
    clock_origin: Instant,
}

impl RealWindowsTreeApi {
    fn new() -> Self {
        Self {
            clock_origin: Instant::now(),
        }
    }
}

struct RealProcessHandle {
    pid: u32,
    handle: OwnedHandle,
}

struct RealJobHandle {
    handle: OwnedHandle,
}

impl WindowsTreeApi for RealWindowsTreeApi {
    type ProcessHandle = RealProcessHandle;
    type JobHandle = RealJobHandle;

    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
        crate::platform::windows::collect_tree_process_infos().map_err(|error| error.to_string())
    }

    fn open_process(&mut self, pid: u32) -> Result<Self::ProcessHandle, WindowsApiError> {
        // AssignProcessToJobObject requires both SET_QUOTA and TERMINATE access,
        // even though tree kill never terminates this handle individually.
        let desired_access = PROCESS_TERMINATE
            | PROCESS_QUERY_LIMITED_INFORMATION
            | PROCESS_SYNCHRONIZE
            | PROCESS_SET_QUOTA;
        let handle = unsafe {
            // SAFETY: OpenProcess takes only value arguments here. The returned
            // handle is checked before it is wrapped for owned close-on-drop.
            OpenProcess(desired_access, 0, pid)
        };
        if handle.is_null() {
            return Err(last_windows_api_error("OpenProcess"));
        }
        let handle = unsafe {
            // SAFETY: OpenProcess returned a non-null process handle owned by this
            // scope. OwnedHandle closes it exactly once on drop.
            OwnedHandle::from_raw_handle(handle)
        };
        Ok(RealProcessHandle { pid, handle })
    }

    fn process_start_marker(&mut self, handle: &Self::ProcessHandle) -> Option<ProcessStartMarker> {
        crate::platform::windows::process_start_time_marker_from_handle(&handle.handle)
    }

    fn process_name(
        &mut self,
        process: &Self::ProcessHandle,
    ) -> Result<Option<String>, WindowsApiError> {
        process_name_from_handle(process)
    }

    fn preflight_job_freeze_thaw(&mut self) -> Result<(), String> {
        // This empty disposable job proves both private class-18 transitions
        // before the target can cross the real job's assignment boundary.
        let job = self.create_job()?;
        self.set_job_frozen(&job, true)?;
        self.set_job_frozen(&job, false)
    }

    fn create_job(&mut self) -> Result<Self::JobHandle, String> {
        let handle = unsafe {
            // SAFETY: null security attributes and name create an unnamed job and
            // pass no Rust-managed memory to Windows.
            CreateJobObjectW(std::ptr::null(), std::ptr::null())
        };
        if handle.is_null() {
            return Err(format!(
                "CreateJobObjectW failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let handle = unsafe {
            // SAFETY: CreateJobObjectW returned a non-null owned handle. OwnedHandle
            // closes it once; the job is not configured with kill-on-close.
            OwnedHandle::from_raw_handle(handle)
        };
        Ok(RealJobHandle { handle })
    }

    fn process_in_job(
        &mut self,
        job: &Self::JobHandle,
        process: &Self::ProcessHandle,
    ) -> Result<bool, WindowsApiError> {
        let mut in_job = 0;
        let result = unsafe {
            // SAFETY: both handles are live and `in_job` is valid for one BOOL
            // write. Windows does not retain the pointer.
            IsProcessInJob(
                process.handle.as_raw_handle(),
                job.handle.as_raw_handle(),
                &raw mut in_job,
            )
        };
        if result == 0 {
            return Err(last_windows_api_error("IsProcessInJob"));
        }
        Ok(in_job != 0)
    }

    fn assign_process(
        &mut self,
        job: &Self::JobHandle,
        process: &Self::ProcessHandle,
    ) -> Result<(), WindowsApiError> {
        let result = unsafe {
            // SAFETY: both handles are live. Assigning a process to a job is the
            // intended Windows API side effect and transfers no Rust ownership.
            AssignProcessToJobObject(job.handle.as_raw_handle(), process.handle.as_raw_handle())
        };
        if result == 0 {
            return Err(last_windows_api_error("AssignProcessToJobObject"));
        }
        Ok(())
    }

    fn set_job_frozen(&mut self, job: &Self::JobHandle, frozen: bool) -> Result<(), String> {
        let information = JobObjectFreezeInformation {
            flags: JOB_OBJECT_FREEZE_OPERATION,
            freeze: u8::from(frozen),
            swap: 0,
            reserved: [0; 2],
            wake_filter: JobObjectWakeFilter {
                high_edge_filter: 0,
                low_edge_filter: 0,
            },
        };
        let size = u32::try_from(std::mem::size_of_val(&information))
            .expect("Job Object freeze information size fits u32");
        let result = unsafe {
            // SAFETY: class 18 is a private Windows ABI. The two u32 wake-filter
            // fields and flags/u8/u8/padding prefix reproduce its 16-byte
            // JOBOBJECT_FREEZE_INFORMATION layout. The live job handle and stack
            // value remain valid for the duration of this bounded call.
            SetInformationJobObject(
                job.handle.as_raw_handle(),
                JobObjectReserved1Information,
                (&raw const information).cast(),
                size,
            )
        };
        if result == 0 {
            return Err(format!(
                "SetInformationJobObject(JobObjectFreezeInformation) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn job_process_ids(&mut self, job: &Self::JobHandle) -> Result<Vec<u32>, JobMembershipError> {
        query_job_process_ids(job)
    }

    fn terminate_job(&mut self, job: &Self::JobHandle) -> Result<(), String> {
        let result = unsafe {
            // SAFETY: the job handle is live and owned by this process. The exit
            // code is a fixed diagnostic value.
            TerminateJobObject(job.handle.as_raw_handle(), WINDOWS_TREE_TERMINATE_EXIT_CODE)
        };
        if result == 0 {
            return Err(format!(
                "TerminateJobObject failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.clock_origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn wait_process_exit(
        &mut self,
        process: &Self::ProcessHandle,
        timeout_ms: u32,
    ) -> WindowsWaitResult {
        let result = unsafe {
            // SAFETY: the process handle is live and was opened with synchronize
            // access. Waiting transfers no ownership and writes no Rust memory.
            WaitForSingleObject(process.handle.as_raw_handle(), timeout_ms)
        };
        match result {
            WAIT_OBJECT_0 => WindowsWaitResult::Exited,
            WAIT_TIMEOUT => WindowsWaitResult::StillRunning,
            WAIT_FAILED => WindowsWaitResult::Failed(format!(
                "WaitForSingleObject(PID {}) failed: {}",
                process.pid,
                std::io::Error::last_os_error()
            )),
            other => WindowsWaitResult::Failed(format!(
                "WaitForSingleObject(PID {}) returned unexpected status {other}",
                process.pid,
            )),
        }
    }
}

fn query_job_process_ids(job: &RealJobHandle) -> Result<Vec<u32>, JobMembershipError> {
    let header_bytes = std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList);
    let entry_bytes = std::mem::size_of::<usize>();
    let mut capacity = 8usize.min(MAX_TREE_PROCESSES);

    for _ in 0..JOB_MEMBERSHIP_QUERY_ATTEMPTS {
        let buffer_bytes = header_bytes
            .checked_add(capacity.saturating_mul(entry_bytes))
            .ok_or_else(|| {
                JobMembershipError::Unreadable("Job membership buffer size overflowed".to_owned())
            })?;
        let words = buffer_bytes.div_ceil(entry_bytes);
        let mut buffer = vec![0usize; words];
        let mut returned_bytes = 0u32;
        let result = unsafe {
            // SAFETY: `buffer` is initialized, aligned for the SDK structure and
            // sized from its actual variable-array offset. Windows writes at most
            // the supplied byte count and does not retain either pointer.
            QueryInformationJobObject(
                job.handle.as_raw_handle(),
                JobObjectBasicProcessIdList,
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer_bytes).expect("bounded Job PID buffer fits u32"),
                &raw mut returned_bytes,
            )
        };
        if result == 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                windows_error_code(&error),
                Some(ERROR_INSUFFICIENT_BUFFER | ERROR_MORE_DATA)
            ) && capacity < MAX_TREE_PROCESSES
            {
                capacity = capacity.saturating_mul(2).min(MAX_TREE_PROCESSES);
                continue;
            }
            return Err(JobMembershipError::Unreadable(format!(
                "QueryInformationJobObject(JobObjectBasicProcessIdList) failed: {error}"
            )));
        }
        if usize::try_from(returned_bytes).expect("u32 return length fits usize") < header_bytes {
            return Err(JobMembershipError::Unreadable(
                "Job membership query returned an incomplete header".to_owned(),
            ));
        }

        let information = unsafe {
            // SAFETY: the successful call initialized at least the fixed header;
            // the allocation is aligned for `usize` and therefore for this type.
            &*buffer.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()
        };
        let assigned = usize::try_from(information.NumberOfAssignedProcesses)
            .expect("u32 process count fits usize");
        let listed = usize::try_from(information.NumberOfProcessIdsInList)
            .expect("u32 process count fits usize");
        if assigned > MAX_TREE_PROCESSES {
            return Err(JobMembershipError::Oversized {
                limit: MAX_TREE_PROCESSES,
            });
        }
        if listed > assigned || listed > capacity {
            return Err(JobMembershipError::Unreadable(
                "Job membership query returned inconsistent process counts".to_owned(),
            ));
        }
        if listed < assigned {
            capacity = assigned
                .max(capacity.saturating_mul(2))
                .min(MAX_TREE_PROCESSES);
            continue;
        }

        let first_entry = header_bytes / entry_bytes;
        let process_ids = &buffer[first_entry..first_entry + listed];
        let mut pids = Vec::with_capacity(listed);
        for &pid in process_ids {
            let pid = u32::try_from(pid).map_err(|_| {
                JobMembershipError::Unreadable(
                    "Job membership contained a PID outside the Windows PID range".to_owned(),
                )
            })?;
            if pid == 0 {
                return Err(JobMembershipError::Unreadable(
                    "Job membership contained PID zero".to_owned(),
                ));
            }
            pids.push(pid);
        }
        pids.sort_unstable();
        if pids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(JobMembershipError::Unreadable(
                "Job membership contained a duplicate PID".to_owned(),
            ));
        }
        return Ok(pids);
    }

    Err(JobMembershipError::Raced)
}

fn process_name_from_handle(
    process: &RealProcessHandle,
) -> Result<Option<String>, WindowsApiError> {
    let mut capacity = 260usize;
    loop {
        let mut path = vec![0u16; capacity];
        let mut length = u32::try_from(path.len()).expect("bounded image path fits u32");
        let result = unsafe {
            // SAFETY: the process handle has query access, the UTF-16 buffer is
            // initialized and writable for `length` elements, and no pointer is retained.
            QueryFullProcessImageNameW(
                process.handle.as_raw_handle(),
                PROCESS_NAME_WIN32,
                path.as_mut_ptr(),
                &raw mut length,
            )
        };
        if result != 0 {
            path.truncate(usize::try_from(length).expect("u32 path length fits usize"));
            let path = OsString::from_wide(&path);
            return Ok(Path::new(&path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()));
        }
        let error = std::io::Error::last_os_error();
        if windows_error_code(&error) == Some(ERROR_INSUFFICIENT_BUFFER)
            && capacity < PROCESS_IMAGE_PATH_CODE_UNITS_MAX
        {
            capacity = capacity
                .saturating_mul(2)
                .min(PROCESS_IMAGE_PATH_CODE_UNITS_MAX);
            continue;
        }
        return Err(windows_api_error("QueryFullProcessImageNameW", &error));
    }
}

fn last_windows_api_error(operation: &str) -> WindowsApiError {
    windows_api_error(operation, &std::io::Error::last_os_error())
}

fn windows_api_error(operation: &str, error: &std::io::Error) -> WindowsApiError {
    match windows_error_code(error) {
        Some(ERROR_INVALID_PARAMETER) => WindowsApiError::NotFound,
        Some(ERROR_ACCESS_DENIED) => WindowsApiError::PermissionDenied,
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => {
            WindowsApiError::PermissionDenied
        }
        _ => WindowsApiError::Other(format!("{operation} failed: {error}")),
    }
}

fn windows_error_code(error: &std::io::Error) -> Option<u32> {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
}

#[cfg(test)]
mod tests {
    use super::{
        JobMembershipError, RealWindowsTreeApi, WindowsApiError, WindowsTreeApi,
        WindowsTreeCleanupIssue, WindowsTreeKillOutcome, WindowsTreePostCommitIssue,
        WindowsTreeTerminationState, WindowsWaitResult, execute_tree_kill_with,
    };
    use crate::model::{PermissionStatus, Platform};
    use crate::process::KillTarget;
    use crate::tree::TreeProcessInfo;
    use std::collections::{HashMap, HashSet, VecDeque};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Event {
        PreflightFreezeCapability,
        CreateJob,
        Assign(u32),
        FreezeJob(bool),
        TerminateJob,
        Wait(u32, u32),
        SpawnedDescendant { parent_pid: u32, child_pid: u32 },
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct FakeProcessHandle {
        pid: u32,
        start_marker: crate::observation::ProcessStartMarker,
    }

    #[derive(Default)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "each bool scripts one independent fake-API failure mode"
    )]
    struct FakeApi {
        snapshots: Vec<Vec<TreeProcessInfo>>,
        snapshot_errors: HashMap<usize, String>,
        next_snapshot: usize,
        current_markers: HashMap<u32, crate::observation::ProcessStartMarker>,
        marker_overrides: HashMap<u32, crate::observation::ProcessStartMarker>,
        names: HashMap<FakeProcessHandle, String>,
        name_results: HashMap<FakeProcessHandle, VecDeque<Result<Option<String>, WindowsApiError>>>,
        deny_name: HashSet<u32>,
        events: Vec<Event>,
        deny_assign: HashSet<u32>,
        fail_root_assign: bool,
        preflight_error: Option<String>,
        fail_terminate_job: bool,
        fail_freeze_job: bool,
        fail_thaw_job: bool,
        already_in_job: HashSet<FakeProcessHandle>,
        membership_results: VecDeque<Result<Vec<u32>, JobMembershipError>>,
        force_not_in_job: HashSet<u32>,
        fail_in_job: HashSet<u32>,
        wait_results: HashMap<u32, VecDeque<WindowsWaitResult>>,
        wait_elapsed_ms: HashMap<u32, VecDeque<u32>>,
        wait_counts: HashMap<u32, usize>,
        spawn_on_wait: Option<(u32, usize, u32)>,
        now_ms: u64,
        job_terminated: bool,
    }

    impl FakeApi {
        fn new(snapshots: Vec<Vec<TreeProcessInfo>>) -> Self {
            let names = snapshots
                .iter()
                .flat_map(|snapshot| snapshot.iter())
                .filter_map(|info| {
                    Some((
                        FakeProcessHandle {
                            pid: info.pid,
                            start_marker: info.start_time_marker?,
                        },
                        info.process_name.clone()?,
                    ))
                })
                .collect();
            Self {
                snapshots,
                names,
                ..Self::default()
            }
        }

        fn handle(pid: u32, marker: u64) -> FakeProcessHandle {
            FakeProcessHandle {
                pid,
                start_marker: crate::observation::ProcessStartMarker::windows(marker).unwrap(),
            }
        }

        fn contain(&mut self, pid: u32, marker: u64) {
            self.already_in_job.insert(Self::handle(pid, marker));
        }

        fn set_name(&mut self, pid: u32, marker: u64, name: impl Into<String>) {
            self.names.insert(Self::handle(pid, marker), name.into());
        }

        fn remove_name(&mut self, pid: u32, marker: u64) {
            self.names.remove(&Self::handle(pid, marker));
        }
    }

    impl WindowsTreeApi for FakeApi {
        type ProcessHandle = FakeProcessHandle;
        type JobHandle = ();

        fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
            if let Some(error) = self.snapshot_errors.get(&self.next_snapshot).cloned() {
                self.next_snapshot += 1;
                return Err(error);
            }
            let index = self
                .next_snapshot
                .min(self.snapshots.len().saturating_sub(1));
            self.next_snapshot += 1;
            let snapshot = self.snapshots.get(index).cloned().unwrap_or_default();
            self.current_markers = snapshot
                .iter()
                .filter_map(|info| Some((info.pid, info.start_time_marker?)))
                .collect();
            Ok(snapshot)
        }

        fn open_process(&mut self, pid: u32) -> Result<Self::ProcessHandle, WindowsApiError> {
            self.marker_overrides
                .get(&pid)
                .or_else(|| self.current_markers.get(&pid))
                .copied()
                .map(|start_marker| FakeProcessHandle { pid, start_marker })
                .ok_or(WindowsApiError::NotFound)
        }

        fn process_start_marker(
            &mut self,
            handle: &Self::ProcessHandle,
        ) -> Option<crate::observation::ProcessStartMarker> {
            Some(handle.start_marker)
        }

        fn process_name(
            &mut self,
            handle: &Self::ProcessHandle,
        ) -> Result<Option<String>, WindowsApiError> {
            if self.deny_name.contains(&handle.pid) {
                return Err(WindowsApiError::PermissionDenied);
            }
            if let Some(results) = self.name_results.get_mut(handle)
                && let Some(result) = results.pop_front()
            {
                return result;
            }
            Ok(self.names.get(handle).cloned())
        }

        fn preflight_job_freeze_thaw(&mut self) -> Result<(), String> {
            self.events.push(Event::PreflightFreezeCapability);
            match &self.preflight_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn create_job(&mut self) -> Result<Self::JobHandle, String> {
            self.events.push(Event::CreateJob);
            Ok(())
        }

        fn process_in_job(
            &mut self,
            _job: &Self::JobHandle,
            process: &Self::ProcessHandle,
        ) -> Result<bool, WindowsApiError> {
            if self.fail_in_job.contains(&process.pid) {
                return Err(WindowsApiError::Other(
                    "containment query failed".to_owned(),
                ));
            }
            if self.force_not_in_job.contains(&process.pid) {
                return Ok(false);
            }
            Ok(self.already_in_job.contains(process))
        }

        fn assign_process(
            &mut self,
            _job: &Self::JobHandle,
            process: &Self::ProcessHandle,
        ) -> Result<(), WindowsApiError> {
            self.events.push(Event::Assign(process.pid));
            if process.pid == 100 && self.fail_root_assign {
                return Err(WindowsApiError::Other("root cannot join job".to_owned()));
            }
            if self.deny_assign.contains(&process.pid) {
                return Err(WindowsApiError::Other("member cannot join job".to_owned()));
            }
            self.already_in_job.insert(*process);
            Ok(())
        }

        fn job_process_ids(
            &mut self,
            _job: &Self::JobHandle,
        ) -> Result<Vec<u32>, JobMembershipError> {
            if let Some(result) = self.membership_results.pop_front() {
                return result;
            }
            let mut pids = self
                .already_in_job
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>();
            pids.sort_unstable();
            pids.dedup();
            Ok(pids)
        }

        fn terminate_job(&mut self, _job: &Self::JobHandle) -> Result<(), String> {
            self.events.push(Event::TerminateJob);
            if self.fail_terminate_job {
                return Err("job termination failed".to_owned());
            }
            self.job_terminated = true;
            Ok(())
        }

        fn set_job_frozen(&mut self, _job: &Self::JobHandle, frozen: bool) -> Result<(), String> {
            self.events.push(Event::FreezeJob(frozen));
            if (frozen && self.fail_freeze_job) || (!frozen && self.fail_thaw_job) {
                return Err("job freeze transition failed".to_owned());
            }
            Ok(())
        }

        fn wait_process_exit(
            &mut self,
            process: &Self::ProcessHandle,
            timeout_ms: u32,
        ) -> WindowsWaitResult {
            self.events.push(Event::Wait(process.pid, timeout_ms));
            let wait_count = self.wait_counts.entry(process.pid).or_default();
            *wait_count += 1;
            if let Some((parent_pid, spawn_wait, child_pid)) = self.spawn_on_wait
                && (parent_pid, spawn_wait) == (process.pid, *wait_count)
            {
                self.events.push(Event::SpawnedDescendant {
                    parent_pid,
                    child_pid,
                });
            }
            let elapsed_ms = self
                .wait_elapsed_ms
                .get_mut(&process.pid)
                .and_then(VecDeque::pop_front)
                .unwrap_or(0)
                .min(timeout_ms);
            self.now_ms = self.now_ms.saturating_add(u64::from(elapsed_ms));
            if let Some(results) = self.wait_results.get_mut(&process.pid)
                && let Some(result) = results.pop_front()
            {
                return result;
            }
            if self.job_terminated {
                WindowsWaitResult::Exited
            } else {
                WindowsWaitResult::StillRunning
            }
        }

        fn now_ms(&mut self) -> u64 {
            self.now_ms
        }
    }

    fn info(pid: u32, parent_pid: Option<u32>, marker: u64) -> TreeProcessInfo {
        TreeProcessInfo {
            pid,
            parent_pid,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some(format!("p{pid}")),
            start_time_marker: crate::observation::ProcessStartMarker::windows(marker).ok(),
            owner_uid: None,
            process_group: None,
        }
    }

    fn root() -> KillTarget {
        KillTarget {
            pid: 100,
            process_name: Some("p100".to_owned()),
            platform: Platform::Windows,
            permission: PermissionStatus::Full,
            protected: false,
            system_process: false,
            ports: Vec::new(),
            owner_uid: None,
            process_start_time_marker: crate::observation::ProcessStartMarker::windows(100).ok(),
            child_count: 0,
            children_truncated: false,
        }
    }

    #[test]
    fn root_assignment_is_the_commit_boundary() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.fail_root_assign = true;

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert!(matches!(
            outcome,
            WindowsTreeKillOutcome::CommitFailed { .. }
        ));
        assert_eq!(
            api.events,
            vec![
                Event::PreflightFreezeCapability,
                Event::CreateJob,
                Event::Assign(100)
            ]
        );
    }

    #[test]
    fn native_empty_job_freeze_thaw_preflight_is_supported() {
        let mut api = RealWindowsTreeApi::new();

        api.preflight_job_freeze_thaw()
            .expect("this Windows host must support empty Job Object freeze and thaw");
    }

    #[test]
    fn freeze_capability_preflight_failure_refuses_before_root_assignment() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.preflight_error = Some("class 18 is unavailable".to_owned());

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(
            outcome,
            WindowsTreeKillOutcome::FreezeCapabilityUnavailable {
                error: "class 18 is unavailable".to_owned(),
            }
        );
        assert_eq!(api.events, vec![Event::PreflightFreezeCapability]);
        assert!(!api.job_terminated);
    }

    #[test]
    fn root_snapshot_identity_drift_refuses_before_job_creation() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 200), info(101, Some(100), 201)]]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(outcome, WindowsTreeKillOutcome::TargetChanged { pid: 100 });
        assert!(api.events.is_empty());
    }

    #[test]
    fn root_handle_identity_drift_refuses_before_job_creation() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.marker_overrides.insert(
            100,
            crate::observation::ProcessStartMarker::windows(200).unwrap(),
        );

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(outcome, WindowsTreeKillOutcome::TargetChanged { pid: 100 });
        assert!(api.events.is_empty());
    }

    #[test]
    fn missing_fresh_name_refuses_with_zero_delivery_or_job_termination() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.remove_name(101, 101);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(
            outcome,
            WindowsTreeKillOutcome::PartialMetadata { pid: 101 }
        );
        assert!(api.events.is_empty());
        assert!(!api.job_terminated);
    }

    #[test]
    fn denied_fresh_name_refuses_distinctly_with_zero_delivery_or_job_termination() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.deny_name.insert(101);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(
            outcome,
            WindowsTreeKillOutcome::PermissionDenied { pid: 101 }
        );
        assert!(api.events.is_empty());
        assert!(!api.job_terminated);
    }

    #[test]
    fn oversized_fresh_name_refuses_with_zero_delivery_or_job_termination() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.set_name(
            101,
            101,
            "x".repeat(crate::observation::PROTECTION_NAME_MAX_BYTES + 1),
        );

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(
            outcome,
            WindowsTreeKillOutcome::PartialMetadata { pid: 101 }
        );
        assert!(api.events.is_empty());
        assert!(!api.job_terminated);
    }

    #[test]
    fn live_assignment_failure_prevents_descendant_spawning_during_fallback() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.deny_assign.insert(101);
        api.wait_results.insert(
            101,
            VecDeque::from([
                WindowsWaitResult::StillRunning,
                WindowsWaitResult::StillRunning,
            ]),
        );
        api.spawn_on_wait = Some((101, 2, 102));

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert_eq!(
            report.termination_state,
            WindowsTreeTerminationState::Withheld
        );
        assert_eq!(report.not_terminated, vec![100, 101]);
        assert!(!api.events.contains(&Event::TerminateJob));
        assert!(!api.events.contains(&Event::FreezeJob(true)));
        assert!(!api.events.contains(&Event::SpawnedDescendant {
            parent_pid: 101,
            child_pid: 102,
        }));
        assert_eq!(api.wait_counts.get(&101), Some(&1));
    }

    #[test]
    fn frozen_final_window_refuses_late_protected_child() {
        let initial = vec![info(100, None, 100), info(101, Some(100), 101)];
        let late = vec![
            info(100, None, 100),
            info(101, Some(100), 101),
            info(102, Some(100), 102),
        ];
        let mut api = FakeApi::new(vec![initial.clone(), initial.clone(), initial, late]);
        api.contain(102, 102);

        let outcome = execute_tree_kill_with(&root(), &["p102".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("post-commit protection refusal returns a report");
        };
        assert!(report.termination_state.is_withheld());
        assert!(report.not_terminated.contains(&100));
        assert!(report.not_terminated.contains(&101));
        assert!(report.not_terminated.contains(&102));
        assert!(!api.events.contains(&Event::TerminateJob));
        let freeze = api
            .events
            .iter()
            .position(|event| *event == Event::FreezeJob(true))
            .expect("job is frozen before the final window");
        let thaw = api
            .events
            .iter()
            .position(|event| *event == Event::FreezeJob(false))
            .expect("withheld job is thawed");
        assert!(freeze < thaw);
    }

    #[test]
    fn yes_skip_withholds_all_termination_when_a_late_child_adds_a_warning() {
        let initial = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut late_system_child = info(102, Some(100), 102);
        late_system_child.process_name = Some("spoolsv.exe".to_owned());
        let late = vec![
            info(100, None, 100),
            info(101, Some(100), 101),
            late_system_child,
        ];
        let mut api = FakeApi::new(vec![initial, late]);
        api.deny_assign.insert(101);

        let outcome = execute_tree_kill_with(&root(), &[], false, true, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("post-commit warning refusal returns a report");
        };
        assert!(report.termination_state.is_withheld());
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::FreshConfirmationRequired)
        );
        assert!(report.not_terminated.contains(&101));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn real_job_freeze_failure_withholds_job_termination() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.fail_freeze_job = true;
        api.fail_thaw_job = true;

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("post-commit freeze failure returns a report");
        };
        assert!(report.termination_state.is_withheld());
        assert_eq!(report.not_terminated, vec![100, 101]);
        assert!(!api.events.contains(&Event::TerminateJob));
        assert!(matches!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::SnapshotFailed(ref error))
                if error.contains("freezing committed Job Object failed")
        ));
        assert_eq!(report.secondary_post_commit_issue, None);
        assert!(matches!(
            report.cleanup_issue,
            Some(WindowsTreeCleanupIssue::WithheldJobThawFailed(ref error))
                if error == "job freeze transition failed"
        ));
        assert_eq!(
            api.events
                .iter()
                .filter(|event| **event == Event::FreezeJob(false))
                .count(),
            1,
            "a failed private freeze transition must trigger exactly one best-effort thaw"
        );
    }

    #[test]
    fn freeze_failure_after_primary_issue_is_retained_as_secondary() {
        let first = vec![info(100, None, 100)];
        let with_protected = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, with_protected]);
        api.fail_freeze_job = true;

        let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("post-commit issues return a report");
        };
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::ProtectedDescendant {
                pid: 101,
                name: Some("p101".to_owned()),
            })
        );
        assert!(matches!(
            report.secondary_post_commit_issue,
            Some(WindowsTreePostCommitIssue::SnapshotFailed(ref error))
                if error.contains("freezing committed Job Object failed")
        ));
        assert!(api.events.contains(&Event::FreezeJob(false)));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn frozen_sweep_failure_after_primary_issue_is_retained_as_secondary() {
        let first = vec![info(100, None, 100)];
        let with_protected = vec![info(100, None, 100), info(101, Some(100), 101)];
        let with_unknown = vec![info(100, None, 100), info(102, Some(100), 102)];
        let mut api = FakeApi::new(vec![first, with_protected, with_unknown]);
        api.remove_name(102, 102);

        let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("post-commit issues return a report");
        };
        assert!(matches!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::ProtectedDescendant { pid: 101, .. })
        ));
        assert_eq!(
            report.secondary_post_commit_issue,
            Some(WindowsTreePostCommitIssue::PartialMetadata { pid: 102 })
        );
        assert!(api.events.contains(&Event::FreezeJob(true)));
        assert!(api.events.contains(&Event::FreezeJob(false)));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn withheld_thaw_failure_preserves_primary_issue_and_avoids_job_termination() {
        let first = vec![info(100, None, 100)];
        let late = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first.clone(), first.clone(), first, late]);
        api.contain(101, 101);
        api.fail_thaw_job = true;

        let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("withheld termination returns a report");
        };
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::ProtectedDescendant {
                pid: 101,
                name: Some("p101".to_owned()),
            })
        );
        assert!(matches!(
            report.cleanup_issue,
            Some(WindowsTreeCleanupIssue::WithheldJobThawFailed(ref error))
                if error == "job freeze transition failed"
        ));
        assert!(api.events.contains(&Event::FreezeJob(true)));
        assert!(api.events.contains(&Event::FreezeJob(false)));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn failed_job_termination_thaw_failure_is_reported_separately() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
        api.fail_terminate_job = true;
        api.fail_thaw_job = true;

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::JobTerminateFailed { error, report } = outcome else {
            panic!("expected failed job termination");
        };
        assert_eq!(error, "job termination failed");
        assert_eq!(report.post_commit_issue, None);
        assert!(matches!(
            report.cleanup_issue,
            Some(WindowsTreeCleanupIssue::FailedTerminationThawFailed(ref thaw_error))
                if thaw_error == "job freeze transition failed"
        ));
        assert_eq!(
            api.events
                .iter()
                .filter(|event| **event == Event::TerminateJob)
                .count(),
            1
        );
        assert!(!api.job_terminated);
    }

    #[test]
    fn failed_job_termination_preserves_assigned_and_already_exited_members() {
        let snapshot = vec![
            info(100, None, 100),
            info(101, Some(100), 101),
            info(102, Some(100), 102),
        ];
        let after_exit = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![snapshot, after_exit]);
        api.deny_assign.insert(102);
        api.wait_results
            .insert(102, VecDeque::from([WindowsWaitResult::Exited]));
        api.fail_terminate_job = true;

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::JobTerminateFailed { error, report } = outcome else {
            panic!("expected failed job termination");
        };
        assert_eq!(error, "job termination failed");
        assert_eq!(report.total, 3);
        assert!(report.job_terminated_pids.is_empty());
        assert_eq!(report.already_exited_pids, vec![102]);
        assert_eq!(report.not_terminated, vec![100, 101]);
        assert!(!report.termination_state.is_complete());
        assert!(api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn report_waits_share_one_total_deadline() {
        let snapshot = vec![
            info(100, None, 100),
            info(101, Some(100), 101),
            info(102, Some(100), 102),
        ];
        let mut api = FakeApi::new(vec![snapshot]);
        api.wait_results
            .insert(100, VecDeque::from([WindowsWaitResult::Exited]));
        api.wait_results
            .insert(101, VecDeque::from([WindowsWaitResult::Exited]));
        api.wait_results
            .insert(102, VecDeque::from([WindowsWaitResult::StillRunning]));
        api.wait_elapsed_ms.insert(100, VecDeque::from([2_000]));
        api.wait_elapsed_ms.insert(101, VecDeque::from([3_000]));

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert_eq!(report.job_terminated_pids, vec![100, 101]);
        assert_eq!(report.not_terminated, vec![102]);
        assert!(!report.termination_state.is_complete());
        assert!(api.events.contains(&Event::Wait(100, 5_000)));
        assert!(api.events.contains(&Event::Wait(101, 3_000)));
        assert!(api.events.contains(&Event::Wait(102, 0)));
    }

    #[test]
    fn exited_member_after_assign_failure_is_not_reported_alive() {
        let mut api = FakeApi::new(vec![
            vec![info(100, None, 100), info(101, Some(100), 101)],
            vec![info(100, None, 100)],
        ]);
        api.deny_assign.insert(101);
        api.wait_results
            .insert(101, VecDeque::from([WindowsWaitResult::Exited]));

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert_eq!(report.already_exited_pids, vec![101]);
        assert!(report.not_terminated.is_empty());
        assert!(report.termination_state.is_complete());
        assert!(api.events.contains(&Event::Wait(101, 0)));
    }

    #[test]
    fn live_uncontained_member_is_not_retried_even_if_it_would_exit_later() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.deny_assign.insert(101);
        api.wait_results.insert(
            101,
            VecDeque::from([WindowsWaitResult::StillRunning, WindowsWaitResult::Exited]),
        );

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert!(report.already_exited_pids.is_empty());
        assert_eq!(report.not_terminated, vec![100, 101]);
        assert_eq!(
            report.termination_state,
            WindowsTreeTerminationState::Withheld
        );
        assert!(!api.events.contains(&Event::TerminateJob));
        assert_eq!(api.wait_counts.get(&101), Some(&1));
    }

    #[test]
    fn already_contained_late_child_terminates_with_the_job() {
        let first = vec![info(100, None, 100)];
        let second = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second]);
        api.contain(101, 101);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert_eq!(report.job_terminated_pids, vec![100, 101]);
        assert!(api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn protected_late_child_withholds_final_job_termination() {
        let first = vec![info(100, None, 100)];
        let second = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second]);

        let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert_eq!(
            report.termination_state,
            WindowsTreeTerminationState::Withheld
        );
        assert_eq!(report.not_terminated, vec![100, 101]);
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::ProtectedDescendant {
                pid: 101,
                name: Some("p101".to_owned()),
            })
        );
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn protected_late_child_already_in_job_is_not_reported_alive() {
        let first = vec![info(100, None, 100)];
        let second = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second]);
        api.contain(101, 101);

        let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert!(!report.termination_state.is_complete());
        assert_eq!(report.not_terminated, vec![100, 101]);
        assert!(report.job_terminated_pids.is_empty());
        assert!(report.termination_state.is_withheld());
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::ProtectedDescendant {
                pid: 101,
                name: Some("p101".to_owned()),
            })
        );
        assert!(!api.events.contains(&Event::TerminateJob));
        assert!(!api.job_terminated);
    }

    #[test]
    fn newly_protected_late_child_uses_fresh_name_and_withholds_termination() {
        let first = vec![info(100, None, 100)];
        let second = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second]);
        api.set_name(101, 101, "lsass.exe");
        api.contain(101, 101);

        let outcome =
            execute_tree_kill_with(&root(), &["lsass.exe".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected truthful contained partial report");
        };
        assert!(report.termination_state.is_withheld());
        assert_eq!(report.not_terminated, vec![100, 101]);
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::ProtectedDescendant {
                pid: 101,
                name: Some("lsass.exe".to_owned()),
            })
        );
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn unknown_late_contained_child_withholds_all_termination() {
        let first = vec![info(100, None, 100)];
        let second = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second]);
        api.remove_name(101, 101);
        api.contain(101, 101);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected truthful contained partial report");
        };
        assert!(report.termination_state.is_withheld());
        assert_eq!(report.not_terminated, vec![100, 101]);
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::PartialMetadata { pid: 101 })
        );
        assert!(!api.events.contains(&Event::TerminateJob));
        assert!(!api.job_terminated);
    }

    #[test]
    fn protected_late_child_with_unknown_job_state_withholds_all_termination() {
        let first = vec![info(100, None, 100)];
        let second = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second]);
        api.set_name(101, 101, "lsass.exe");
        api.fail_in_job.insert(101);

        let outcome =
            execute_tree_kill_with(&root(), &["lsass.exe".to_owned()], false, false, &mut api);
        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected fail-closed partial report");
        };
        assert!(report.termination_state.is_withheld());
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn unknown_late_child_with_unknown_job_state_withholds_all_termination() {
        let first = vec![info(100, None, 100)];
        let second = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second]);
        api.remove_name(101, 101);
        api.fail_in_job.insert(101);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);
        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected fail-closed partial report");
        };
        assert!(report.termination_state.is_withheld());
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn post_commit_snapshot_error_withholds_job_termination() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
        api.snapshot_errors
            .insert(1, "injected sweep snapshot failure".to_owned());

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);
        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected post-commit report");
        };
        assert!(report.termination_state.is_withheld());
        assert!(matches!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::SnapshotFailed(_))
        ));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn sweep_pass_exhaustion_withholds_job_termination() {
        let mut snapshots = vec![vec![info(100, None, 100)]];
        let mut current = snapshots[0].clone();
        for offset in 0..super::WINDOWS_TREE_SWEEP_PASSES {
            let pid = 101 + u32::try_from(offset).expect("test offset fits u32");
            current.push(info(pid, Some(100), u64::from(pid)));
            snapshots.push(current.clone());
        }
        let mut api = FakeApi::new(snapshots);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);
        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected post-commit report");
        };
        assert!(report.termination_state.is_withheld());
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::SweepPassLimit {
                limit: super::WINDOWS_TREE_SWEEP_PASSES,
            })
        );
        assert_eq!(
            api.next_snapshot,
            1 + super::WINDOWS_TREE_SWEEP_PASSES,
            "the pre-commit snapshot plus exactly eight sweep snapshots are allowed"
        );
        assert!(!api.events.contains(&Event::FreezeJob(true)));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn pre_freeze_and_frozen_sweeps_share_exact_total_pass_budget() {
        let root_only = vec![info(100, None, 100)];
        let mut snapshots = vec![root_only.clone(), root_only.clone(), root_only];
        let mut grown = snapshots[2].clone();
        for offset in 0..(super::WINDOWS_TREE_SWEEP_PASSES - 2) {
            let pid = 101 + u32::try_from(offset).expect("test offset fits u32");
            grown.push(info(pid, Some(100), u64::from(pid)));
            snapshots.push(grown.clone());
        }
        let mut api = FakeApi::new(snapshots);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("budget exhaustion returns a post-commit report");
        };
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::SweepPassLimit {
                limit: super::WINDOWS_TREE_SWEEP_PASSES,
            })
        );
        assert_eq!(
            api.next_snapshot,
            1 + super::WINDOWS_TREE_SWEEP_PASSES,
            "the invocation must never start sweep snapshot nine"
        );
        assert!(api.events.contains(&Event::FreezeJob(true)));
        assert!(api.events.contains(&Event::FreezeJob(false)));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn final_window_snapshot_catches_late_protected_child() {
        let first = vec![info(100, None, 100)];
        let second = first.clone();
        let third = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second, third]);
        api.contain(101, 101);

        let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], false, false, &mut api);
        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected post-commit report");
        };
        assert!(report.termination_state.is_withheld());
        assert_eq!(report.not_terminated, vec![100, 101]);
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn final_reconciliation_keeps_a_descendant_whose_intermediate_parent_exited() {
        let initial = vec![
            info(100, None, 100),
            info(101, Some(100), 101),
            info(102, Some(101), 102),
        ];
        let reparented = vec![info(100, None, 100), info(102, Some(1), 102)];
        let mut api = FakeApi::new(vec![
            initial.clone(),
            initial.clone(),
            initial.clone(),
            initial.clone(),
            initial,
            reparented,
        ]);
        api.wait_results
            .insert(101, VecDeque::from([WindowsWaitResult::Exited]));
        api.membership_results = VecDeque::from([Ok(vec![100, 102]), Ok(vec![100, 102])]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert!(api.events.contains(&Event::TerminateJob));
        assert_eq!(report.already_exited_pids, vec![101]);
        assert_eq!(report.job_terminated_pids, vec![100, 102]);
    }

    #[test]
    fn exact_membership_finds_unseen_inherited_protected_child() {
        let root_only = vec![info(100, None, 100)];
        let final_snapshot = vec![info(100, None, 100), info(102, Some(101), 102)];
        let mut api = FakeApi::new(vec![
            root_only.clone(),
            root_only.clone(),
            root_only.clone(),
            root_only.clone(),
            root_only,
            final_snapshot,
        ]);
        api.contain(102, 102);

        let outcome = execute_tree_kill_with(&root(), &["p102".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("protected inherited member returns a withheld report");
        };
        assert!(report.termination_state.is_withheld());
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::ProtectedDescendant {
                pid: 102,
                name: Some("p102".to_owned()),
            })
        );
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn final_graph_never_traverses_a_reused_root_pid() {
        let original = vec![info(100, None, 100)];
        let mut replacement_root = info(100, None, 200);
        replacement_root.process_name = Some("lsass.exe".to_owned());
        let replacement = vec![replacement_root, info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![
            original.clone(),
            original.clone(),
            original.clone(),
            original.clone(),
            original,
            replacement,
        ]);

        let outcome =
            execute_tree_kill_with(&root(), &["lsass.exe".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("PID reuse after commit returns a withheld report");
        };
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::TargetChanged { pid: 100 })
        );
        assert!(!api.events.contains(&Event::Assign(101)));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn final_graph_never_traverses_a_reused_intermediate_pid() {
        let original = vec![info(100, None, 100), info(101, Some(100), 101)];
        let replacement = vec![
            info(100, None, 100),
            info(101, Some(100), 201),
            info(102, Some(101), 102),
        ];
        let mut api = FakeApi::new(vec![
            original.clone(),
            original.clone(),
            original.clone(),
            original.clone(),
            original,
            replacement,
        ]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("intermediate PID reuse returns a withheld report");
        };
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::TargetChanged { pid: 101 })
        );
        assert!(!api.events.contains(&Event::Assign(102)));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn exact_membership_mismatch_withholds_termination() {
        let snapshot = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![snapshot]);
        api.membership_results = VecDeque::from([Ok(vec![100])]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("membership mismatch returns a withheld report");
        };
        assert!(report.termination_state.is_withheld());
        assert!(matches!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::SnapshotFailed(ref error))
                if error.contains("PID 101 was absent from exact frozen Job membership")
        ));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn oversized_exact_membership_withholds_termination() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
        api.membership_results = VecDeque::from([Err(JobMembershipError::Oversized {
            limit: crate::tree::MAX_TREE_PROCESSES,
        })]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("oversized membership returns a withheld report");
        };
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::Truncated {
                limit: crate::tree::MAX_TREE_PROCESSES,
            })
        );
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn changing_exact_membership_during_validation_withholds_termination() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
        api.membership_results = VecDeque::from([Ok(vec![100]), Ok(Vec::new())]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("raced membership returns a withheld report");
        };
        assert!(matches!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::SnapshotFailed(ref error))
                if error.contains("membership changed during final reconciliation")
        ));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn survivor_after_successful_job_termination_is_thawed_and_reported() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
        api.wait_results
            .insert(100, VecDeque::from([WindowsWaitResult::StillRunning]));

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("successful job termination returns a report");
        };
        assert_eq!(
            report.cleanup_issue,
            Some(WindowsTreeCleanupIssue::PostTerminationSurvivorsThawed {
                pids: vec![100],
                wait_errors: Vec::new(),
            })
        );
        assert!(api.events.contains(&Event::TerminateJob));
        assert!(api.events.contains(&Event::FreezeJob(false)));
    }

    #[test]
    fn survivor_thaw_failure_after_successful_job_termination_is_distinct() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
        api.wait_results.insert(
            100,
            VecDeque::from([WindowsWaitResult::Failed("wait failed".to_owned())]),
        );
        api.fail_thaw_job = true;

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("successful job termination returns a report");
        };
        assert_eq!(
            report.cleanup_issue,
            Some(WindowsTreeCleanupIssue::PostTerminationSurvivorThawFailed {
                pids: vec![100],
                wait_errors: vec![(100, "wait failed".to_owned())],
                error: "job freeze transition failed".to_owned(),
            })
        );
    }

    #[test]
    fn protected_root_change_after_commit_keeps_typed_confirmation_result() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100)]]);
        api.name_results.insert(
            FakeApi::handle(100, 100),
            VecDeque::from([
                Ok(Some("p100".to_owned())),
                Ok(Some("lsass.exe".to_owned())),
            ]),
        );

        let outcome =
            execute_tree_kill_with(&root(), &["lsass.exe".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("post-commit protected root returns a withheld report");
        };
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::ProtectedRoot {
                pid: 100,
                name: Some("lsass.exe".to_owned()),
            })
        );
        assert!(report.termination_state.is_withheld());
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn final_reconciliation_refuses_unproven_live_membership_and_thaws() {
        let snapshot = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![snapshot]);
        api.force_not_in_job.insert(101);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("containment refusal returns a report");
        };
        assert!(report.termination_state.is_withheld());
        assert!(!api.events.contains(&Event::TerminateJob));
        let freeze = api
            .events
            .iter()
            .position(|event| *event == Event::FreezeJob(true))
            .expect("job was frozen");
        let thaw = api
            .events
            .iter()
            .position(|event| *event == Event::FreezeJob(false))
            .expect("refusal thawed the job");
        assert!(freeze < thaw);
    }

    #[test]
    fn final_reconciliation_snapshot_error_always_thaws_the_job() {
        let snapshot = vec![info(100, None, 100)];
        let mut api = FakeApi::new(vec![snapshot]);
        api.snapshot_errors
            .insert(5, "final reconciliation failed".to_owned());

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("post-freeze error returns a report");
        };
        assert!(report.termination_state.is_withheld());
        assert!(matches!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::SnapshotFailed(ref error))
                if error == "final reconciliation failed"
        ));
        assert!(api.events.contains(&Event::FreezeJob(true)));
        assert!(api.events.contains(&Event::FreezeJob(false)));
        assert!(!api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn partial_metadata_refuses_before_job_creation() {
        let mut partial = info(101, Some(100), 101);
        partial.start_time_marker = None;
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), partial]]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(
            outcome,
            WindowsTreeKillOutcome::PartialMetadata { pid: 101 }
        );
        assert!(api.events.is_empty());
    }

    #[test]
    fn unverified_parent_edge_into_preview_refuses_before_job_creation() {
        let mut partial_child = info(101, None, 101);
        partial_child.start_time_marker = None;
        partial_child.unverified_parent_pid = Some(100);
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), partial_child]]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(
            outcome,
            WindowsTreeKillOutcome::PartialMetadata { pid: 101 }
        );
        assert!(api.events.is_empty());
    }
}
