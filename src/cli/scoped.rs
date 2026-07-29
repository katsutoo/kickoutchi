//! Scoped kills: `--tree` and `--group`. One confirmed root authorizes a
//! bounded set of processes, so beyond the single-kill gates these flows add
//! typed scope words, fresh-scan re-gating, and (on Unix) the freeze-first
//! executor from `crate::tree`; Windows uses Job Object containment instead.

#[cfg(windows)]
use std::io;
use std::io::Write;

use crate::collector;
use crate::config::Config;
use crate::display::sanitize;
use crate::model::{
    PermissionStatus, Platform, PortEntry, PortEntryView, ProcessContext, SystemProcessCheck,
};
use crate::observation::MetadataProfile;
use crate::platform;
use crate::process::{
    self, CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, KillMode, KillTarget,
    TerminationOutcome,
};
use crate::tree;
#[cfg(windows)]
use crate::tree::TreeKillOutcome as TreeRefusal;

#[cfg(windows)]
use super::kill::post_kill_refresh_status_message;
use super::kill::{
    KillTargetError, print_post_kill_refresh_status, print_target_error, read_confirmation_line,
    resolve_kill_target, revalidate_cli_target,
};
use super::{ExitReason, KillArgs, TREE_HOST_PLATFORM};

/// Longest child preview printed in the tree confirmation banner.
const TREE_PREVIEW_MAX: usize = 12;

/// What the user must do to authorize a tree kill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeConfirmation {
    /// Type a literal word (`tree` for terminate, `force` for force).
    TypedWord(&'static str),
    /// The root is protected: type its PID or process name, as with a
    /// single-process protected kill.
    ProtectedRoot,
}

/// The confirmation gate for a tree kill, decided before the prompt is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeConfirmDecision {
    /// `--yes` on an all-clear tree: proceed without a prompt.
    Skip,
    /// Ask the user to satisfy this requirement.
    PromptWord(&'static str),
    /// Protected root requires the protected confirmation and then the tree word.
    PromptProtectedThenWord(&'static str),
    /// `--yes` cannot authorize a protected root: refuse.
    RefuseProtectedYes,
}

/// Facts established by confirmation and needed by the fresh
/// execution-time gates. `skipped_prompt` is deliberately separate from
/// `args.yes`: `--yes` can still fall back to a typed prompt when the preview has
/// warnings, and that explicit word should not be treated as a silent skip.
#[derive(Debug, Clone, Copy)]
struct ScopedConfirmationFacts {
    protected_confirmed: bool,
    skipped_prompt: bool,
}

/// The confirmation facts in the pipeline's vocabulary, so the final frozen-set
/// policy can re-apply exactly what the prompt (or its skip) authorized.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scope_authorization(confirmation: ScopedConfirmationFacts) -> tree::ScopeAuthorization {
    tree::ScopeAuthorization {
        protected_root_confirmed: confirmation.protected_confirmed,
        prompt_skipped: confirmation.skipped_prompt,
    }
}

/// The injected seams for a tree kill, bundled so the entry point stays under
/// the argument-count limit and mirrors `KillCollectors` in the `kill` module.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct TreeKillSeams<CollectContext, Prompt, CollectKillPorts, CollectPorts> {
    collect_context: CollectContext,
    prompt: Prompt,
    collect_kill_ports: CollectKillPorts,
    collect_ports: CollectPorts,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn run_tree_kill(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
) -> ExitReason {
    let mode = if args.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };
    #[cfg(target_os = "linux")]
    let mut ops = crate::platform::linux::LinuxTreeOps::new();
    #[cfg(target_os = "macos")]
    let mut ops = crate::platform::macos::MacosTreeOps::new();
    run_tree_kill_with(
        args,
        config,
        entries,
        mode,
        &mut ops,
        TreeKillSeams {
            collect_context: platform::collect_process_context,
            prompt: prompt_tree_confirmation,
            collect_kill_ports: || collector::collect_kill_ports(args.pid, args.port),
            collect_ports: || collector::collect_ports_with_profile(MetadataProfile::IdentityOnly),
        },
    )
}

#[cfg(windows)]
pub(super) fn run_tree_kill(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
) -> ExitReason {
    let mode = if args.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };
    run_windows_tree_kill(args, config, entries, mode)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_tree_kill_with<Ops, CollectContext, Prompt, CollectKillPorts, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    mode: KillMode,
    ops: &mut Ops,
    mut seams: TreeKillSeams<CollectContext, Prompt, CollectKillPorts, CollectPorts>,
) -> ExitReason
where
    Ops: tree::TreeProcessOps,
    CollectContext: FnMut(u32) -> ProcessContext,
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
    CollectKillPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    // Preview snapshot: informational only. Execution re-enumerates under the
    // freeze and is the authority; this drives the banner and the pre-flight
    // refusals, which have zero side effects.
    let snapshot = match ops.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!(
                "error: enumerating the process tree failed: {}",
                sanitize(&error)
            );
            return ExitReason::Failure;
        }
    };

    let root = match resolve_scoped_kill_root(
        args,
        config,
        entries,
        &snapshot,
        &mut seams.collect_context,
    ) {
        Ok(target) => target,
        Err(reason) => return reason,
    };
    let preview = match tree::plan_process_tree(
        root.pid,
        &snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_TREE_PROCESSES,
    ) {
        Ok(preview) => preview,
        Err(tree::TreePlanError::RootMissing) => {
            eprintln!(
                "error: root PID {} is no longer running; nothing to terminate",
                root.pid
            );
            return ExitReason::NoMatch;
        }
        Err(tree::TreePlanError::SnapshotLimitExceeded { limit }) => {
            eprintln!("error: process snapshot exceeds the bounded {limit}-PID index");
            return ExitReason::Failure;
        }
    };

    if let Some(reason) = scoped_preflight_refusal(&preview, "tree") {
        return reason;
    }

    let confirmation = match confirm_tree_kill(&root, &preview, mode, args.yes, &mut seams.prompt) {
        Ok(confirmation) => confirmation,
        Err(reason) => return reason,
    };

    if let Err(outcome) = tree::pin_root_before_revalidation(root.pid, ops) {
        return map_tree_outcome(&root, mode, &outcome, &mut seams.collect_ports);
    }

    let fresh_root = match revalidate_tree_root_before_freeze(
        args,
        config,
        &root,
        confirmation,
        &mut seams.collect_context,
        &mut seams.collect_kill_ports,
        ops,
    ) {
        Ok(root) => root,
        Err(outcome) => return map_tree_outcome(&root, mode, &outcome, &mut seams.collect_ports),
    };

    let outcome = tree::execute_tree_kill(
        &fresh_root,
        mode,
        &config.protected_processes,
        fresh_root.platform,
        scope_authorization(confirmation),
        ops,
    );
    map_tree_outcome(&fresh_root, mode, &outcome, &mut seams.collect_ports)
}

#[cfg(windows)]
fn run_windows_tree_kill(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    mode: KillMode,
) -> ExitReason {
    run_windows_tree_kill_with(
        args,
        config,
        entries,
        mode,
        WindowsTreeKillSeams {
            collect_tree: crate::platform::windows::collect_tree_process_infos,
            collect_context: platform::collect_process_context,
            prompt: prompt_tree_confirmation,
            collect_kill_ports: || collector::collect_kill_ports(args.pid, args.port),
            collect_ports: || collector::collect_ports_with_profile(MetadataProfile::IdentityOnly),
            prepare_root: process::prepare_termination,
            execute: crate::windows_tree::execute_tree_kill,
        },
    )
}

#[cfg(windows)]
struct WindowsTreeKillSeams<
    CollectTree,
    CollectContext,
    Prompt,
    CollectKillPorts,
    CollectPorts,
    PrepareRoot,
    Execute,
> {
    collect_tree: CollectTree,
    collect_context: CollectContext,
    prompt: Prompt,
    collect_kill_ports: CollectKillPorts,
    collect_ports: CollectPorts,
    prepare_root: PrepareRoot,
    execute: Execute,
}

#[cfg(windows)]
fn run_windows_tree_kill_with<
    CollectTree,
    CollectContext,
    Prompt,
    CollectKillPorts,
    CollectPorts,
    PrepareRoot,
    Execute,
    RootHandle,
>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    mode: KillMode,
    mut seams: WindowsTreeKillSeams<
        CollectTree,
        CollectContext,
        Prompt,
        CollectKillPorts,
        CollectPorts,
        PrepareRoot,
        Execute,
    >,
) -> ExitReason
where
    CollectTree: FnMut() -> Result<Vec<tree::TreeProcessInfo>, collector::CollectorError>,
    CollectContext: FnMut(u32) -> ProcessContext,
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
    CollectKillPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    PrepareRoot: FnMut(u32) -> Result<RootHandle, TerminationOutcome>,
    Execute:
        FnMut(&KillTarget, &[String], bool, bool) -> crate::windows_tree::WindowsTreeKillOutcome,
{
    let snapshot = match (seams.collect_tree)() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("error: enumerating the process table failed: {error}");
            return ExitReason::Failure;
        }
    };
    let root = match resolve_scoped_kill_root(
        args,
        config,
        entries,
        &snapshot,
        &mut seams.collect_context,
    ) {
        Ok(target) => target,
        Err(reason) => return reason,
    };
    let preview = match tree::plan_process_tree(
        root.pid,
        &snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_TREE_PROCESSES,
    ) {
        Ok(preview) => preview,
        Err(tree::TreePlanError::RootMissing) => {
            eprintln!(
                "error: root PID {} is no longer running; nothing to terminate",
                root.pid
            );
            return ExitReason::NoMatch;
        }
        Err(tree::TreePlanError::SnapshotLimitExceeded { limit }) => {
            eprintln!("error: process snapshot exceeds the bounded {limit}-PID index");
            return ExitReason::Failure;
        }
    };

    if let Some(reason) = scoped_preflight_refusal(&preview, "tree") {
        return reason;
    }

    let confirmation = match confirm_tree_kill(&root, &preview, mode, args.yes, &mut seams.prompt) {
        Ok(confirmation) => confirmation,
        Err(reason) => return reason,
    };

    // A port-selected root must be retained before the final authoritative
    // endpoint collection. PID mode deliberately keeps its existing path.
    let prepared_root = if args.port.is_some() {
        match (seams.prepare_root)(root.pid) {
            Ok(handle) => Some(handle),
            Err(outcome) => {
                let outcome = crate::windows_tree::WindowsTreeKillOutcome::from_precommit_outcome(
                    tree_outcome_from_termination(&root, outcome),
                );
                return map_windows_tree_outcome(&root, mode, &outcome, &mut seams.collect_ports);
            }
        }
    } else {
        None
    };

    let fresh_root = match revalidate_windows_tree_root_before_commit(
        args,
        config,
        &root,
        confirmation,
        &mut seams.collect_tree,
        &mut seams.collect_context,
        &mut seams.collect_kill_ports,
    ) {
        Ok(root) => root,
        Err(outcome) => {
            return map_windows_tree_outcome(&root, mode, &outcome, &mut seams.collect_ports);
        }
    };

    let outcome = (seams.execute)(
        &fresh_root,
        &config.protected_processes,
        confirmation.protected_confirmed,
        confirmation.skipped_prompt,
    );
    drop(prepared_root);
    map_windows_tree_outcome(&fresh_root, mode, &outcome, &mut seams.collect_ports)
}

#[cfg(windows)]
fn revalidate_windows_tree_root_before_commit<CollectTree, CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    confirmation: ScopedConfirmationFacts,
    collect_tree: &mut CollectTree,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
) -> Result<KillTarget, crate::windows_tree::WindowsTreeKillOutcome>
where
    CollectTree: FnMut() -> Result<Vec<tree::TreeProcessInfo>, collector::CollectorError>,
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let fresh_root = if confirmed.ports.is_empty() {
        let snapshot = collect_tree().map_err(|error| {
            crate::windows_tree::WindowsTreeKillOutcome::snapshot_failed(error.to_string())
        })?;
        let root = revalidate_portless_tree_root(confirmed, &snapshot, &config.protected_processes)
            .map_err(crate::windows_tree::WindowsTreeKillOutcome::from_precommit_outcome)?;
        windows_fresh_tree_gates(&root, &snapshot, config, confirmation)?;
        root
    } else {
        let root = revalidate_cli_target(args, config, confirmed, collect_context, collect_ports)
            .map_err(|outcome| {
            let outcome = tree_outcome_from_termination(confirmed, outcome);
            crate::windows_tree::WindowsTreeKillOutcome::from_precommit_outcome(outcome)
        })?;
        let snapshot = collect_tree().map_err(|error| {
            crate::windows_tree::WindowsTreeKillOutcome::snapshot_failed(error.to_string())
        })?;
        windows_fresh_tree_gates(&root, &snapshot, config, confirmation)?;
        root
    };
    Ok(fresh_root)
}

#[cfg(windows)]
fn windows_fresh_tree_gates(
    root: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    config: &Config,
    confirmation: ScopedConfirmationFacts,
) -> Result<(), crate::windows_tree::WindowsTreeKillOutcome> {
    let preview = tree::plan_process_tree(
        root.pid,
        snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_TREE_PROCESSES,
    )
    .map_err(tree::plan_error_outcome)
    .map_err(crate::windows_tree::WindowsTreeKillOutcome::from_precommit_outcome)?;
    tree::preflight_outcome(&preview)
        .map_err(crate::windows_tree::WindowsTreeKillOutcome::from_precommit_outcome)?;
    tree::root_protection_outcome(&preview, confirmation.protected_confirmed)
        .map_err(crate::windows_tree::WindowsTreeKillOutcome::from_precommit_outcome)?;
    fresh_tree_yes_outcome(root, &preview, confirmation)
        .map_err(crate::windows_tree::WindowsTreeKillOutcome::from_precommit_outcome)?;
    if let Some(pid) = preview
        .preview_nodes(preview.len())
        .iter()
        .find_map(|node| {
            let info = snapshot.iter().find(|info| info.pid == node.pid)?;
            (info.process_name.is_none() || info.start_time_marker.is_none()).then_some(info.pid)
        })
    {
        return Err(crate::windows_tree::WindowsTreeKillOutcome::Refused(
            TreeRefusal::PartialMetadata { pid },
        ));
    }
    Ok(())
}

/// Run the confirmation flow. On success, the returned bool records whether
/// the protected-root confirmation was actually completed — the execution-time
/// protection guard needs that fact, because a root can be classified as
/// protected by a fresh scan even when the confirmed port row could not be.
fn confirm_tree_kill<Prompt>(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    mode: KillMode,
    yes: bool,
    prompt: &mut Prompt,
) -> Result<ScopedConfirmationFacts, ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
{
    confirm_scoped_kill(
        root,
        preview,
        tree_confirmation(root, preview, mode, yes),
        || print_tree_kill_banner(root, preview, mode),
        prompt,
    )
}

/// Execute the confirmation decision shared by tree and group scope.
///
/// Scope-specific policy chooses the decision and banner before this point;
/// this helper only preserves the identical prompt ordering and records the
/// exact authorization facts consumed by fresh revalidation.
fn confirm_scoped_kill<Prompt, PrintBanner>(
    root: &KillTarget,
    members: &tree::ProcessTreeTarget,
    decision: TreeConfirmDecision,
    print_banner: PrintBanner,
    prompt: &mut Prompt,
) -> Result<ScopedConfirmationFacts, ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
    PrintBanner: FnOnce(),
{
    if decision == TreeConfirmDecision::RefuseProtectedYes {
        eprintln!(
            "error: {} is protected; --yes cannot bypass protected-process confirmation",
            root.identity(),
        );
        return Err(ExitReason::ProtectedNeedsConfirmation);
    }

    print_banner();
    match decision {
        TreeConfirmDecision::RefuseProtectedYes => {
            unreachable!("protected --yes refusal returned before printing a banner")
        }
        TreeConfirmDecision::Skip => Ok(ScopedConfirmationFacts {
            protected_confirmed: false,
            skipped_prompt: true,
        }),
        TreeConfirmDecision::PromptWord(word) => {
            prompt_tree_step(root, members, TreeConfirmation::TypedWord(word), prompt)?;
            Ok(ScopedConfirmationFacts {
                protected_confirmed: false,
                skipped_prompt: false,
            })
        }
        TreeConfirmDecision::PromptProtectedThenWord(word) => {
            prompt_tree_step(root, members, TreeConfirmation::ProtectedRoot, prompt)?;
            prompt_tree_step(root, members, TreeConfirmation::TypedWord(word), prompt)?;
            Ok(ScopedConfirmationFacts {
                protected_confirmed: true,
                skipped_prompt: false,
            })
        }
    }
}

fn prompt_tree_step<Prompt>(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    requirement: TreeConfirmation,
    prompt: &mut Prompt,
) -> Result<(), ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
{
    let confirmed = match prompt(root, preview, requirement) {
        Ok(confirmed) => confirmed,
        Err(error) => {
            eprintln!("error: reading confirmation failed: {error}");
            return Err(ExitReason::Failure);
        }
    };
    if confirmed {
        Ok(())
    } else {
        eprintln!("kill cancelled");
        Err(ExitReason::KillCancelled)
    }
}

/// Resolve the confirmed root for a scoped (tree or group) kill.
///
/// Port targets resolve through the socket table exactly like a single kill;
/// a `--pid` target that owns no visible port falls back to the process-table
/// snapshot, because scoped kills legitimately start from portless
/// supervisors. Refusals are printed here and returned as the exit reason.
fn resolve_scoped_kill_root<CollectContext>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    snapshot: &[tree::TreeProcessInfo],
    collect_context: &mut CollectContext,
) -> Result<KillTarget, ExitReason>
where
    CollectContext: FnMut(u32) -> ProcessContext,
{
    match (
        resolve_kill_target(args, entries, collect_context),
        args.pid,
    ) {
        (Ok(target), _) => Ok(target),
        (Err(KillTargetError::NoMatch), Some(pid)) => {
            match resolve_pid_tree_root_from_snapshot(pid, snapshot, &config.protected_processes) {
                Ok(target) => Ok(target),
                Err(KillTargetError::NoMatch) => {
                    eprintln!("error: root PID {pid} is no longer running; nothing to terminate");
                    Err(ExitReason::NoMatch)
                }
                Err(error) => Err(print_target_error(error)),
            }
        }
        (Err(KillTargetError::NoMatch), None) => {
            eprintln!("error: no open port matches the requested target");
            Err(ExitReason::NoMatch)
        }
        (Err(error), _) => Err(print_target_error(error)),
    }
}

fn resolve_pid_tree_root_from_snapshot(
    pid: u32,
    snapshot: &[tree::TreeProcessInfo],
    protected_names: &[String],
) -> Result<KillTarget, KillTargetError> {
    if let Some(reason) = process::unsafe_pid_reason(pid) {
        return Err(KillTargetError::UnsafePid(reason));
    }
    let Some(info) = snapshot.iter().find(|info| info.pid == pid) else {
        return Err(KillTargetError::NoMatch);
    };
    Ok(kill_target_from_tree_info(info, protected_names))
}

fn kill_target_from_tree_info(
    info: &tree::TreeProcessInfo,
    protected_names: &[String],
) -> KillTarget {
    let protected = info.process_name.as_deref().is_some_and(|name| {
        crate::protection::is_protected_process_name(TREE_HOST_PLATFORM, name, protected_names)
    });
    let system_process = SystemProcessCheck {
        platform: TREE_HOST_PLATFORM,
        pid: Some(info.pid),
        parent_pid: info.parent_pid,
        process_name: info.process_name.as_deref(),
        parent_process_name: info.parent_process_name.as_deref(),
    }
    .is_system_process();
    // Honest metadata status: identity fields decide partial-vs-full, and the
    // snapshot's owner UID reaches the target so the ownership warning can
    // fire for a portless supervisor owned by another user. A missing UID is
    // not partial metadata by itself — it only mutes the ownership warning.
    let complete = info.process_name.is_some() && info.start_time_marker.is_some();
    KillTarget {
        pid: info.pid,
        process_name: info.process_name.clone(),
        platform: TREE_HOST_PLATFORM,
        permission: if complete {
            PermissionStatus::Full
        } else {
            PermissionStatus::Partial
        },
        protected,
        system_process,
        ports: Vec::new(),
        owner_uid: info.owner_uid,
        process_start_time_marker: info.start_time_marker,
        child_count: 0,
        children_truncated: false,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn revalidate_tree_root_before_freeze<Ops, CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    confirmation: ScopedConfirmationFacts,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
    ops: &mut Ops,
) -> Result<KillTarget, tree::TreeKillOutcome>
where
    Ops: tree::TreeProcessOps,
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let fresh_root = if confirmed.ports.is_empty() {
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Tree {
            root_pid: confirmed.pid,
        });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        let root =
            revalidate_portless_tree_root(confirmed, &snapshot, &config.protected_processes)?;
        fresh_tree_gates(&root, &snapshot, config, confirmation)?;
        root
    } else {
        let root = revalidate_cli_target(args, config, confirmed, collect_context, collect_ports)
            .map_err(|outcome| tree_outcome_from_termination(confirmed, outcome))?;
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Tree { root_pid: root.pid });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        fresh_tree_gates(&root, &snapshot, config, confirmation)?;
        root
    };
    Ok(fresh_root)
}

/// The fresh-scan gates for a freeze-first tree kill: the plan must still
/// build, and the pre-flight, root-protection, and `--yes`-skip rules must
/// re-pass against the fresh snapshot.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fresh_tree_gates(
    root: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    config: &Config,
    confirmation: ScopedConfirmationFacts,
) -> Result<(), tree::TreeKillOutcome> {
    let preview = tree::plan_process_tree(
        root.pid,
        snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_TREE_PROCESSES,
    )
    .map_err(tree::plan_error_outcome)?;
    tree::preflight_outcome(&preview)?;
    tree::root_protection_outcome(&preview, confirmation.protected_confirmed)?;
    fresh_tree_yes_outcome(root, &preview, confirmation)
}

fn fresh_tree_yes_outcome(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    confirmation: ScopedConfirmationFacts,
) -> Result<(), tree::TreeKillOutcome> {
    if confirmation.skipped_prompt && !tree_yes_skip_allowed(root, preview) {
        return Err(tree::TreeKillOutcome::FreshConfirmationRequired);
    }
    Ok(())
}

/// Translate a single-kill revalidation refusal into the scoped-kill outcome
/// vocabulary, so tree and group revalidation report identically.
fn tree_outcome_from_termination(
    confirmed: &KillTarget,
    outcome: TerminationOutcome,
) -> tree::TreeKillOutcome {
    match outcome {
        TerminationOutcome::ProtectedProcess => tree::TreeKillOutcome::ProtectedRoot {
            pid: confirmed.pid,
            name: confirmed.process_name.clone(),
        },
        TerminationOutcome::UnsafePid(reason) => tree::TreeKillOutcome::UnsafePid {
            pid: confirmed.pid,
            reason,
        },
        TerminationOutcome::OwnershipUnavailable => {
            tree::TreeKillOutcome::OwnershipUnavailable { pid: confirmed.pid }
        }
        TerminationOutcome::AlreadyExited => tree::TreeKillOutcome::RootAlreadyExited,
        TerminationOutcome::TargetChanged
        | TerminationOutcome::Success
        | TerminationOutcome::Cancelled => {
            tree::TreeKillOutcome::TargetChanged { pid: confirmed.pid }
        }
        TerminationOutcome::PermissionDenied => {
            tree::TreeKillOutcome::PermissionDenied { pid: confirmed.pid }
        }
        TerminationOutcome::UnknownFailure(error) => tree::TreeKillOutcome::SnapshotFailed(error),
        TerminationOutcome::ThawFailed { pid, prior } => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                tree::TreeKillOutcome::ThawFailed {
                    pids: vec![pid],
                    cause: Box::new(tree_outcome_from_termination(confirmed, *prior)),
                }
            }
            #[cfg(windows)]
            {
                let _ = (pid, prior);
                tree::TreeKillOutcome::SnapshotFailed(
                    "unexpected thaw failure in Windows tree preparation".to_owned(),
                )
            }
        }
    }
}

fn revalidate_portless_tree_root(
    confirmed: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    protected_names: &[String],
) -> Result<KillTarget, tree::TreeKillOutcome> {
    let Some(info) = snapshot.iter().find(|info| info.pid == confirmed.pid) else {
        return Err(tree::TreeKillOutcome::RootAlreadyExited);
    };
    let (Some(confirmed_start), Some(fresh_start)) =
        (confirmed.process_start_time_marker, info.start_time_marker)
    else {
        return Err(tree::TreeKillOutcome::PartialMetadata { pid: confirmed.pid });
    };
    if confirmed_start != fresh_start {
        return Err(tree::TreeKillOutcome::TargetChanged { pid: confirmed.pid });
    }
    if let Some(expected) = confirmed.process_name.as_deref()
        && info.process_name.as_deref() != Some(expected)
    {
        return Err(tree::TreeKillOutcome::TargetChanged { pid: confirmed.pid });
    }
    let fresh = kill_target_from_tree_info(info, protected_names);
    if fresh.protected && !confirmed.protected {
        return Err(tree::TreeKillOutcome::ProtectedRoot {
            pid: fresh.pid,
            name: fresh.process_name.clone(),
        });
    }
    Ok(fresh)
}

/// Refuse a tree or group that fails a pre-flight rule, before any signal is
/// sent. `scope_noun` is `"tree"` or `"group"` and only changes the wording;
/// the gates and exit codes are identical for both scopes.
fn scoped_preflight_refusal(
    preview: &tree::ProcessTreeTarget,
    scope_noun: &str,
) -> Option<ExitReason> {
    tree::preflight_outcome(preview).err().map(|outcome| match outcome {
        tree::TreeKillOutcome::Truncated { limit } => {
            eprintln!(
                "error: process {scope_noun} exceeds the {limit} process cap; refusing to kill a partial {scope_noun}",
            );
            ExitReason::Failure
        }
        tree::TreeKillOutcome::UnsafePid { pid, .. } => {
            eprintln!("error: process {scope_noun} contains unsafe PID {pid}; refusing {scope_noun} kill");
            ExitReason::Failure
        }
        tree::TreeKillOutcome::ProtectedDescendant { pid, name } => {
            let name = sanitize(name.as_deref().unwrap_or("<unknown>"));
            eprintln!("error: process {scope_noun} contains protected process PID {pid} ({name}); refusing {scope_noun} kill");
            ExitReason::ProtectedNeedsConfirmation
        }
        // preflight_outcome only produces the gates above today; if it ever
        // grows one, refuse loudly rather than exiting without a word.
        other => {
            eprintln!("error: process {scope_noun} pre-flight refused the kill: {other:?}");
            ExitReason::Failure
        }
    })
}

fn tree_confirmation(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    mode: KillMode,
    yes: bool,
) -> TreeConfirmDecision {
    // Protected if *either* reader says so: the port-row policy (which needs a
    // readable row name) or the tree scan's root classification. The two can
    // disagree on partial-metadata rows, and protection must win either way.
    if root.protected || preview.root().is_some_and(|node| node.protected) {
        if yes {
            return TreeConfirmDecision::RefuseProtectedYes;
        }
        return TreeConfirmDecision::PromptProtectedThenWord(tree::tree_scope_word(mode));
    }

    // Terminate asks for "tree"; force asks for "force" — the more dangerous
    // action wants the more deliberate word.
    let word = tree::tree_scope_word(mode);
    if yes && tree_yes_skip_allowed(root, preview) {
        return TreeConfirmDecision::Skip;
    }
    TreeConfirmDecision::PromptWord(word)
}

fn tree_yes_skip_allowed(root: &KillTarget, preview: &tree::ProcessTreeTarget) -> bool {
    !preview.has_warnings() && !root_has_tree_yes_blocking_warning(root)
}

fn root_has_tree_yes_blocking_warning(root: &KillTarget) -> bool {
    // The child-count notice is informational under tree scope (the tree
    // preview supersedes it); every other warning kind blocks a `--yes` skip.
    root.warnings()
        .iter()
        .any(|warning| !matches!(warning, process::KillWarning::HasChildren { .. }))
}

fn print_tree_kill_banner(root: &KillTarget, preview: &tree::ProcessTreeTarget, mode: KillMode) {
    eprintln!(
        "{} process tree from {}",
        mode.action_label(),
        root.identity()
    );
    eprintln!("Scope: tree ({} processes)", preview.len());
    eprintln!("Ports: {}", sanitize(&root.ports_text()));
    let mut command = format!("kick kill --pid {} --tree", root.pid);
    if mode == KillMode::Force {
        command.push_str(" --force");
    }
    eprintln!("Command: {}", sanitize(&command));
    for node in preview.preview_nodes(TREE_PREVIEW_MAX) {
        let indent = "  ".repeat(node.depth + 1);
        let name = sanitize(node.process_name.as_deref().unwrap_or("<unknown>"));
        eprintln!("{indent}PID {} ({name})", node.pid);
    }
    if preview.len() > TREE_PREVIEW_MAX {
        eprintln!("  ... and {} more", preview.len() - TREE_PREVIEW_MAX);
    }
    if let Some(warning) = mode.force_warning(root.platform) {
        eprintln!("Warning: {}", sanitize(warning));
    }
    if root.platform == Platform::Windows {
        eprintln!(
            "Warning: Windows tree kill uses Job Object containment and hard termination; close apps normally first when possible."
        );
        eprintln!(
            "Warning: Windows may also terminate newly spawned job-contained children that were not visible in this preview."
        );
    }
    if preview.has_system_process() {
        eprintln!(
            "Warning: tree includes system/service processes; verify this is safe to terminate."
        );
    }
    if let Some(warning) = scoped_owner_warning(preview, "tree") {
        eprintln!("Warning: {warning}.");
    }
    for warning in root.warning_lines() {
        eprintln!(
            "Warning: {}.",
            sanitize(&process::tree_scope_warning_text(&warning))
        );
    }
}

fn prompt_tree_confirmation(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    requirement: TreeConfirmation,
) -> std::io::Result<bool> {
    match requirement {
        TreeConfirmation::TypedWord(word) => eprint!(
            "Type {word} to terminate all {} processes, or press Enter to cancel: ",
            preview.len(),
        ),
        TreeConfirmation::ProtectedRoot => eprint!(
            "Protected root: type PID {} or process name {} to confirm: ",
            root.pid,
            sanitize(root.process_name_or_unknown()),
        ),
    }
    std::io::stderr().flush()?;

    let answer = read_confirmation_line(CONFIRMATION_INPUT_MAX_BYTES)?;
    Ok(tree_confirmation_matches(&answer, root, requirement))
}

fn tree_confirmation_matches(
    input: &str,
    root: &KillTarget,
    requirement: TreeConfirmation,
) -> bool {
    match requirement {
        TreeConfirmation::TypedWord(word) => tree::word_confirmation_matches(input, word),
        TreeConfirmation::ProtectedRoot => process::confirmation_input_matches(
            input,
            root,
            ConfirmationRequirement::ProtectedProcess,
        ),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn map_tree_outcome<CollectPorts>(
    root: &KillTarget,
    mode: KillMode,
    outcome: &tree::TreeKillOutcome,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let scope_of_target = format!("the tree rooted at {}", root.identity());
    map_scoped_outcome(root, mode, outcome, "tree", &scope_of_target, collect_ports)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn map_group_outcome<CollectPorts>(
    root: &KillTarget,
    pgid: u32,
    mode: KillMode,
    outcome: &tree::TreeKillOutcome,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let scope_of_target = format!("process group {pgid} of {}", root.identity());
    map_scoped_outcome(
        root,
        mode,
        outcome,
        "group",
        &scope_of_target,
        collect_ports,
    )
}

#[cfg(windows)]
fn map_windows_tree_outcome<CollectPorts>(
    root: &KillTarget,
    _mode: KillMode,
    outcome: &crate::windows_tree::WindowsTreeKillOutcome,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    use crate::windows_tree::WindowsTreeKillOutcome;

    match outcome {
        WindowsTreeKillOutcome::Completed(report) => {
            map_windows_tree_completed_outcome(root, report, collect_ports)
        }
        _ => map_windows_tree_refusal_outcome(root, outcome, collect_ports),
    }
}

#[cfg(windows)]
fn map_windows_tree_completed_outcome<CollectPorts>(
    root: &KillTarget,
    report: &crate::windows_tree::WindowsTreeKillReport,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    if report.termination_state.is_complete() && report.not_terminated.is_empty() {
        eprintln!(
            "terminated {} process(es) in the Windows Job Object for the tree rooted at {}",
            report.job_terminated_pids.len(),
            root.identity(),
        );
        print_post_kill_refresh_status(root, collect_ports);
        return ExitReason::Success;
    }

    eprintln!("{}", windows_tree_partial_report_text(root, report));
    if let Some(issue) = &report.post_commit_issue {
        return windows_post_commit_issue_exit_reason(issue);
    }
    if report.cleanup_issue.is_some() {
        return ExitReason::Failure;
    }
    if report.not_terminated.is_empty() {
        ExitReason::Failure
    } else {
        ExitReason::PermissionDenied
    }
}

#[cfg(windows)]
fn windows_tree_partial_report_text(
    root: &KillTarget,
    report: &crate::windows_tree::WindowsTreeKillReport,
) -> String {
    let job = if report.job_terminated_pids.is_empty() {
        format!("job-terminated 0 of {} observed process(es)", report.total)
    } else {
        format!(
            "job-terminated {} of {} observed process(es) (PIDs: {})",
            report.job_terminated_pids.len(),
            report.total,
            tree::format_pid_list(&report.job_terminated_pids),
        )
    };
    let already_exited = if report.already_exited_pids.is_empty() {
        String::new()
    } else {
        format!(
            "; {} process(es) already exited (PIDs: {})",
            report.already_exited_pids.len(),
            tree::format_pid_list(&report.already_exited_pids),
        )
    };
    let missing = if report.not_terminated.is_empty() {
        String::new()
    } else {
        format!(
            "; PID(s) not confirmed terminated: {}",
            tree::format_pid_list(&report.not_terminated)
        )
    };
    let withheld = if report.termination_state.is_withheld() {
        "; job termination was withheld because strict tree closure could not be established for every observed descendant"
    } else {
        ""
    };
    let post_commit_issue = report
        .post_commit_issue
        .as_ref()
        .map_or_else(String::new, |issue| {
            format!(
                "; post-commit issue: {}",
                windows_post_commit_issue_text(issue)
            )
        });
    let secondary_post_commit_issue =
        report
            .secondary_post_commit_issue
            .as_ref()
            .map_or_else(String::new, |issue| {
                format!(
                    "; secondary post-commit issue: {}",
                    windows_post_commit_issue_text(issue)
                )
            });
    let cleanup_issue = report
        .cleanup_issue
        .as_ref()
        .map_or_else(String::new, |issue| {
            format!("; cleanup issue: {}", windows_cleanup_issue_text(issue))
        });
    format!(
        "warning: Windows tree containment was partial for {}; {job}{already_exited}{missing}{withheld}{post_commit_issue}{secondary_post_commit_issue}{cleanup_issue}",
        root.identity(),
    )
}

#[cfg(windows)]
fn windows_cleanup_issue_text(issue: &crate::windows_tree::WindowsTreeCleanupIssue) -> String {
    use crate::windows_tree::WindowsTreeCleanupIssue;

    match issue {
        WindowsTreeCleanupIssue::WithheldJobThawFailed(error) => format!(
            "thawing the withheld Windows Job Object failed: {}",
            sanitize(error)
        ),
        WindowsTreeCleanupIssue::FailedTerminationThawFailed(error) => format!(
            "thawing the Windows Job Object after TerminateJobObject failed: {}",
            sanitize(error)
        ),
        WindowsTreeCleanupIssue::PostTerminationSurvivorsThawed { pids, wait_errors } => format!(
            "TerminateJobObject returned success but PID(s) {} were not confirmed exited; the job was thawed{}",
            tree::format_pid_list(pids),
            windows_wait_error_suffix(wait_errors),
        ),
        WindowsTreeCleanupIssue::PostTerminationSurvivorThawFailed {
            pids,
            wait_errors,
            error,
        } => format!(
            "TerminateJobObject returned success but PID(s) {} were not confirmed exited, and thawing the job failed: {}{}",
            tree::format_pid_list(pids),
            sanitize(error),
            windows_wait_error_suffix(wait_errors),
        ),
    }
}

#[cfg(windows)]
fn windows_wait_error_suffix(wait_errors: &[(u32, String)]) -> String {
    if wait_errors.is_empty() {
        return String::new();
    }
    let details = wait_errors
        .iter()
        .map(|(pid, error)| format!("PID {pid}: {}", sanitize(error)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("; wait error(s): {details}")
}

#[cfg(windows)]
fn windows_post_commit_issue_text(
    issue: &crate::windows_tree::WindowsTreePostCommitIssue,
) -> String {
    use crate::windows_tree::WindowsTreePostCommitIssue;

    match issue {
        WindowsTreePostCommitIssue::RootAlreadyExited => {
            "root exited during the containment sweep".to_owned()
        }
        WindowsTreePostCommitIssue::PermissionDenied { pid } => {
            format!("permission denied for PID {pid} during the containment sweep")
        }
        WindowsTreePostCommitIssue::TargetChanged { pid } => {
            format!("process identity changed at PID {pid} during the containment sweep")
        }
        WindowsTreePostCommitIssue::Truncated { limit } => {
            format!("tree exceeded {limit} processes after containment was committed")
        }
        WindowsTreePostCommitIssue::SweepPassLimit { limit } => {
            format!("tree did not converge after {limit} containment sweeps")
        }
        WindowsTreePostCommitIssue::UnsafePid { pid, reason } => {
            format!(
                "unsafe PID {pid} appeared after commit: {}",
                reason.message()
            )
        }
        WindowsTreePostCommitIssue::ProtectedDescendant { pid, name } => format!(
            "protected descendant PID {pid} ({}) appeared after commit",
            sanitize(name.as_deref().unwrap_or("<unknown>"))
        ),
        WindowsTreePostCommitIssue::ProtectedRoot { pid, name } => format!(
            "root PID {pid} ({}) became protected after commit and requires fresh confirmation",
            sanitize(name.as_deref().unwrap_or("<unknown>"))
        ),
        WindowsTreePostCommitIssue::FreshConfirmationRequired => {
            "tree gained warnings after --yes; rerun without --yes to review them".to_owned()
        }
        WindowsTreePostCommitIssue::OwnershipUnavailable { pid } => {
            format!("ownership for PID {pid} became unavailable after containment was committed")
        }
        WindowsTreePostCommitIssue::PartialMetadata { pid } => {
            format!("process metadata for PID {pid} became incomplete during the containment sweep")
        }
        WindowsTreePostCommitIssue::SnapshotFailed(error) => format!(
            "enumerating the Windows process tree failed after commit: {}",
            sanitize(error)
        ),
    }
}

#[cfg(windows)]
fn windows_post_commit_issue_exit_reason(
    issue: &crate::windows_tree::WindowsTreePostCommitIssue,
) -> ExitReason {
    use crate::windows_tree::WindowsTreePostCommitIssue;

    match issue {
        WindowsTreePostCommitIssue::ProtectedDescendant { .. }
        | WindowsTreePostCommitIssue::ProtectedRoot { .. } => {
            ExitReason::ProtectedNeedsConfirmation
        }
        WindowsTreePostCommitIssue::PermissionDenied { .. }
        | WindowsTreePostCommitIssue::OwnershipUnavailable { .. } => ExitReason::PermissionDenied,
        WindowsTreePostCommitIssue::RootAlreadyExited
        | WindowsTreePostCommitIssue::TargetChanged { .. }
        | WindowsTreePostCommitIssue::Truncated { .. }
        | WindowsTreePostCommitIssue::SweepPassLimit { .. }
        | WindowsTreePostCommitIssue::UnsafePid { .. }
        | WindowsTreePostCommitIssue::FreshConfirmationRequired
        | WindowsTreePostCommitIssue::PartialMetadata { .. }
        | WindowsTreePostCommitIssue::SnapshotFailed(_) => ExitReason::Failure,
    }
}

#[cfg(windows)]
fn map_windows_tree_refusal_outcome<CollectPorts>(
    root: &KillTarget,
    outcome: &crate::windows_tree::WindowsTreeKillOutcome,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    use crate::windows_tree::WindowsTreeKillOutcome;

    match outcome {
        WindowsTreeKillOutcome::Completed(_) => unreachable!("completed outcome handled above"),
        WindowsTreeKillOutcome::Refused(refusal) => {
            map_windows_tree_refusal(root, refusal, collect_ports)
        }
        WindowsTreeKillOutcome::CommitFailed { .. }
        | WindowsTreeKillOutcome::FreezeCapabilityUnavailable { .. }
        | WindowsTreeKillOutcome::JobTerminateFailed { .. } => {
            let mut stderr = io::stderr().lock();
            map_windows_tree_system_failure(root, outcome, collect_ports, &mut stderr)
        }
    }
}

#[cfg(windows)]
fn map_windows_tree_refusal(
    root: &KillTarget,
    refusal: &TreeRefusal,
    collect_ports: &mut impl FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
) -> ExitReason {
    let cause = sanitize(&refusal.failure_cause_text());
    match refusal {
        TreeRefusal::RootAlreadyExited => {
            eprintln!(
                "{} already exited before containment was committed",
                root.identity(),
            );
            print_post_kill_refresh_status(root, collect_ports);
        }
        TreeRefusal::PermissionDenied { .. } => {
            eprintln!(
                "error: {cause}; no Windows Job Object containment was committed; {}",
                process::permission_denied_hint(root.platform),
            );
        }
        TreeRefusal::TargetChanged { .. }
        | TreeRefusal::SweepPassLimit { .. }
        | TreeRefusal::UnsafePid { .. }
        | TreeRefusal::ProtectedDescendant { .. } => {
            eprintln!("error: {cause}; no Windows Job Object containment was committed");
        }
        TreeRefusal::Truncated { .. } => {
            eprintln!("error: {cause}; refusing to commit a partial Windows process tree");
        }
        TreeRefusal::ProtectedRoot { .. } => {
            eprintln!(
                "error: {cause} and requires PID/name confirmation before Windows containment",
            );
        }
        TreeRefusal::FreshConfirmationRequired => {
            eprintln!(
                "error: {cause}; rerun without --yes to review fresh warnings; no containment was committed",
            );
        }
        TreeRefusal::OwnershipUnavailable { .. } | TreeRefusal::PartialMetadata { .. } => {
            eprintln!("error: {cause} before Windows containment; no termination was sent");
        }
        TreeRefusal::SnapshotFailed(_) => {
            eprintln!(
                "error: enumerating the Windows process tree failed: {cause}; no termination was sent",
            );
        }
    }

    tree_refusal_exit_reason(refusal)
}

#[cfg(windows)]
fn map_windows_tree_system_failure(
    root: &KillTarget,
    outcome: &crate::windows_tree::WindowsTreeKillOutcome,
    collect_ports: &mut impl FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    stderr: &mut impl Write,
) -> ExitReason {
    use crate::windows_tree::WindowsTreeKillOutcome;

    match outcome {
        WindowsTreeKillOutcome::CommitFailed { pid, error } => {
            let _ = writeln!(
                stderr,
                "error: assigning root PID {pid} to the Windows Job Object failed before commit: {}; no termination was sent",
                sanitize(error),
            );
            ExitReason::Failure
        }
        WindowsTreeKillOutcome::FreezeCapabilityUnavailable { error } => {
            let _ = writeln!(
                stderr,
                "error: Windows Job Object freeze/thaw capability is unavailable: {}; no containment was committed and no termination was sent",
                sanitize(error),
            );
            ExitReason::Failure
        }
        WindowsTreeKillOutcome::JobTerminateFailed { error, report } => {
            let _ = writeln!(
                stderr,
                "error: Windows Job Object containment was committed but TerminateJobObject failed: {}",
                sanitize(error),
            );
            let _ = writeln!(stderr, "{}", windows_tree_partial_report_text(root, report));
            if let Some(message) = post_kill_refresh_status_message(root, collect_ports) {
                let _ = writeln!(stderr, "{message}");
            }
            ExitReason::Failure
        }
        WindowsTreeKillOutcome::Completed(_) | WindowsTreeKillOutcome::Refused(_) => {
            unreachable!("non-system Windows tree outcome handled above")
        }
    }
}

/// Shared success/partial-success wording for tree and group delivery reports.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scoped_delivery_summary(
    delivery: &str,
    scope_noun: &str,
    scope_of_target: &str,
    report: &tree::TreeKillReport,
) -> String {
    if report.denied.is_empty() && report.already_exited == 0 {
        return format!(
            "sent {delivery} to {} process(es) in {scope_of_target}",
            report.delivered,
        );
    }

    let exited_suffix = if report.already_exited == 0 {
        String::new()
    } else {
        format!(
            "; {} already exited before final delivery",
            report.already_exited
        )
    };
    let denied_suffix = if report.denied.is_empty() {
        String::new()
    } else {
        format!(
            "; permission denied for PID(s): {}",
            tree::format_pid_list(&report.denied)
        )
    };
    format!(
        "sent {delivery} to {} of {} {scope_noun} process(es){exited_suffix}{denied_suffix}",
        report.delivered, report.total,
    )
}

/// Print the outcome of a scoped (tree or group) kill and map it to the exit
/// contract. One function for both scopes so a refusal can never exit with
/// different codes depending on how the same processes were targeted;
/// `scope_noun` and `scope_of_target` only shape the wording.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive typed scoped-outcome mapping is intentionally centralized"
)]
fn map_scoped_outcome<CollectPorts>(
    root: &KillTarget,
    mode: KillMode,
    outcome: &tree::TreeKillOutcome,
    scope_noun: &str,
    scope_of_target: &str,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    use crate::tree::TreeKillOutcome;

    let delivery = mode.delivery_label(root.platform);
    match outcome {
        TreeKillOutcome::ThawFailed { pids, cause } => {
            eprintln!(
                "error: {}; cleanup could not continue PID(s) {}; they may remain stopped and require SIGCONT",
                sanitize(&cause.failure_cause_text()),
                tree::format_pid_list(pids),
            );
            ExitReason::Failure
        }
        TreeKillOutcome::Completed(report)
            if report.denied.is_empty() && report.thaw_failed.is_empty() =>
        {
            eprintln!(
                "{}",
                scoped_delivery_summary(delivery, scope_noun, scope_of_target, report)
            );
            print_post_kill_refresh_status(root, collect_ports);
            ExitReason::Success
        }
        TreeKillOutcome::Completed(report) => {
            eprintln!(
                "{}",
                scoped_delivery_summary(delivery, scope_noun, scope_of_target, report)
            );
            if report.thaw_failed.is_empty() {
                ExitReason::PermissionDenied
            } else {
                eprintln!(
                    "error: PID(s) {} may remain stopped because SIGCONT failed",
                    tree::format_pid_list(&report.thaw_failed),
                );
                ExitReason::Failure
            }
        }
        TreeKillOutcome::RootAlreadyExited => {
            eprintln!(
                "{} already exited before termination was sent",
                root.identity(),
            );
            print_post_kill_refresh_status(root, collect_ports);
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::PermissionDenied { .. } => {
            eprintln!(
                "error: {}; any frozen process was thawed and no termination was sent; {}",
                sanitize(&outcome.failure_cause_text()),
                process::permission_denied_hint(root.platform),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::TargetChanged { .. } | TreeKillOutcome::SweepPassLimit { .. } => {
            eprintln!(
                "error: {}; the process {scope_noun} was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::Truncated { .. } | TreeKillOutcome::ProtectedDescendant { .. } => {
            eprintln!(
                "error: {}; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::UnsafePid { .. } => {
            eprintln!(
                "error: {} in {scope_noun}; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::ProtectedRoot { .. } => {
            eprintln!(
                "error: {} and requires PID/name confirmation; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::FreshConfirmationRequired => {
            eprintln!(
                "error: {}; rerun without --yes to review fresh warnings; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::OwnershipUnavailable { .. } => {
            eprintln!(
                "error: {} before {delivery}; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::PartialMetadata { .. } => {
            eprintln!(
                "error: {} during {scope_noun} verification; any frozen process was thawed and no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
        TreeKillOutcome::SnapshotFailed(_) => {
            eprintln!(
                "error: enumerating the process {scope_noun} during termination failed: {}; no termination was sent",
                sanitize(&outcome.failure_cause_text()),
            );
            tree_refusal_exit_reason(outcome)
        }
    }
}

fn tree_refusal_exit_reason(outcome: &tree::TreeKillOutcome) -> ExitReason {
    match outcome.refusal_class() {
        Some(tree::TreeRefusalClass::NoMatch) => ExitReason::NoMatch,
        Some(tree::TreeRefusalClass::PermissionDenied) => ExitReason::PermissionDenied,
        Some(tree::TreeRefusalClass::ProtectedNeedsConfirmation) => {
            ExitReason::ProtectedNeedsConfirmation
        }
        Some(tree::TreeRefusalClass::Failure) => ExitReason::Failure,
        None => unreachable!("completed or cleanup outcomes are not refusals"),
    }
}

// The group `--yes` skip ceiling lives in `tree.rs` because the final
// frozen-set policy re-applies it after the sweep; the confirmation gate here
// and that policy must share one number.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::tree::GROUP_YES_SKIP_MAX_PROCESSES;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn run_group_kill(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
) -> ExitReason {
    let mode = if args.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };
    #[cfg(target_os = "linux")]
    let mut ops = crate::platform::linux::LinuxTreeOps::new();
    #[cfg(target_os = "macos")]
    let mut ops = crate::platform::macos::MacosTreeOps::new();
    run_group_kill_with(
        args,
        config,
        entries,
        mode,
        &mut ops,
        TreeKillSeams {
            collect_context: platform::collect_process_context,
            prompt: prompt_group_confirmation,
            collect_kill_ports: || collector::collect_kill_ports(args.pid, args.port),
            collect_ports: || collector::collect_ports_with_profile(MetadataProfile::IdentityOnly),
        },
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_group_kill_with<Ops, CollectContext, Prompt, CollectKillPorts, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    mode: KillMode,
    ops: &mut Ops,
    mut seams: TreeKillSeams<CollectContext, Prompt, CollectKillPorts, CollectPorts>,
) -> ExitReason
where
    Ops: tree::TreeProcessOps,
    CollectContext: FnMut(u32) -> ProcessContext,
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
    CollectKillPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    // Preview snapshot: informational only, exactly like tree scope. Execution
    // re-enumerates under the freeze and is the authority.
    let snapshot = match ops.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!(
                "error: enumerating the process group failed: {}",
                sanitize(&error)
            );
            return ExitReason::Failure;
        }
    };

    let root = match resolve_scoped_kill_root(
        args,
        config,
        entries,
        &snapshot,
        &mut seams.collect_context,
    ) {
        Ok(target) => target,
        Err(reason) => return reason,
    };
    let group = match tree::plan_process_group(
        root.pid,
        &snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_GROUP_PROCESSES,
    ) {
        Ok(group) => group,
        Err(tree::GroupPlanError::RootMissing) => {
            eprintln!(
                "error: root PID {} is no longer running; nothing to terminate",
                root.pid
            );
            return ExitReason::NoMatch;
        }
        Err(tree::GroupPlanError::GroupUnavailable) => {
            eprintln!(
                "error: PID {} has no targetable process group; refusing group kill",
                root.pid
            );
            return ExitReason::Failure;
        }
    };

    if let Some(reason) = scoped_preflight_refusal(group.members(), "group") {
        return reason;
    }

    let confirmation = match confirm_group_kill(&root, &group, mode, args.yes, &mut seams.prompt) {
        Ok(confirmation) => confirmation,
        Err(reason) => return reason,
    };

    if let Err(outcome) = tree::pin_root_before_revalidation(root.pid, ops) {
        return map_group_outcome(
            &root,
            group.pgid(),
            mode,
            &outcome,
            &mut seams.collect_ports,
        );
    }

    let fresh_root = match revalidate_group_root_before_freeze(
        args,
        config,
        &root,
        ConfirmedGroupFacts {
            pgid: group.pgid(),
            confirmation,
        },
        &mut seams.collect_context,
        &mut seams.collect_kill_ports,
        ops,
    ) {
        Ok(root) => root,
        Err(outcome) => {
            return map_group_outcome(
                &root,
                group.pgid(),
                mode,
                &outcome,
                &mut seams.collect_ports,
            );
        }
    };

    let outcome = tree::execute_group_kill(
        &fresh_root,
        group.pgid(),
        mode,
        &config.protected_processes,
        fresh_root.platform,
        scope_authorization(confirmation),
        ops,
    );
    map_group_outcome(
        &fresh_root,
        group.pgid(),
        mode,
        &outcome,
        &mut seams.collect_ports,
    )
}

/// Run the group confirmation flow; mirrors [`confirm_tree_kill`], including
/// the returned protected-root fact.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn confirm_group_kill<Prompt>(
    root: &KillTarget,
    group: &tree::ProcessGroupTarget,
    mode: KillMode,
    yes: bool,
    prompt: &mut Prompt,
) -> Result<ScopedConfirmationFacts, ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
{
    confirm_scoped_kill(
        root,
        group.members(),
        group_confirmation(root, group, mode, yes),
        || print_group_kill_banner(root, group, mode),
        prompt,
    )
}

/// The confirmation gate for a group kill.
///
/// Stricter than tree scope on `--yes`: a process group has no structural tie
/// to the confirmed target, so beyond the tree rules (no warnings anywhere,
/// no protected root) the group must also be tiny before the typed word may
/// be skipped.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn group_confirmation(
    root: &KillTarget,
    group: &tree::ProcessGroupTarget,
    mode: KillMode,
    yes: bool,
) -> TreeConfirmDecision {
    let members = group.members();
    // Protected if *either* reader says so, exactly like tree scope.
    if root.protected || members.root().is_some_and(|node| node.protected) {
        if yes {
            return TreeConfirmDecision::RefuseProtectedYes;
        }
        return TreeConfirmDecision::PromptProtectedThenWord(tree::group_scope_word(mode));
    }

    let word = tree::group_scope_word(mode);
    if yes && group_yes_skip_allowed(root, members) {
        return TreeConfirmDecision::Skip;
    }
    TreeConfirmDecision::PromptWord(word)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn group_yes_skip_allowed(root: &KillTarget, members: &tree::ProcessTreeTarget) -> bool {
    members.len() <= GROUP_YES_SKIP_MAX_PROCESSES
        && !members.has_warnings()
        && !root_has_tree_yes_blocking_warning(root)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn print_group_kill_banner(root: &KillTarget, group: &tree::ProcessGroupTarget, mode: KillMode) {
    let members = group.members();
    eprintln!(
        "{} process group {} of {}",
        mode.action_label(),
        group.pgid(),
        root.identity()
    );
    eprintln!(
        "Scope: group {} ({} processes)",
        group.pgid(),
        members.len()
    );
    eprintln!("Ports: {}", sanitize(&root.ports_text()));
    let mut command = format!("kick kill --pid {} --group", root.pid);
    if mode == KillMode::Force {
        command.push_str(" --force");
    }
    eprintln!("Command: {}", sanitize(&command));
    // Every member, uncapped here (the builder already bounds the set): a process
    // group can contain unrelated commands launched from the same shell, so
    // the confirmation must show the entire blast radius.
    for node in members.preview_nodes(members.len()) {
        let name = sanitize(node.process_name.as_deref().unwrap_or("<unknown>"));
        let root_marker = if node.depth == 0 {
            " [confirmed target]"
        } else {
            ""
        };
        eprintln!("  PID {} ({name}){root_marker}", node.pid);
    }
    if let Some(warning) = mode.force_warning(root.platform) {
        eprintln!("Warning: {}", sanitize(warning));
    }
    if members.has_system_process() {
        eprintln!(
            "Warning: group includes system/service processes; verify this is safe to terminate."
        );
    }
    if let Some(warning) = scoped_owner_warning(members, "group") {
        eprintln!("Warning: {warning}.");
    }
    eprintln!(
        "Warning: a process group can include unrelated processes started from the same shell; review every member above."
    );
    for warning in root.warning_lines() {
        eprintln!(
            "Warning: {}.",
            sanitize(&process::group_scope_warning_text(&warning))
        );
    }
}

fn scoped_owner_warning(preview: &tree::ProcessTreeTarget, scope_noun: &str) -> Option<String> {
    #[cfg(windows)]
    {
        let _ = preview;
        let _ = scope_noun;
        None
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let current_uid = process::current_user_id();
        let mut count = 0_usize;
        let mut first = None;
        for node in preview.preview_nodes(preview.len()) {
            let Some(owner_uid) = node.owner_uid else {
                continue;
            };
            if owner_uid == current_uid {
                continue;
            }
            count += 1;
            first.get_or_insert((node.pid, owner_uid));
        }

        let (pid, owner_uid) = first?;
        Some(format!(
            "{scope_noun} includes {count} process(es) owned by another uid; first is PID {pid} owned by uid {owner_uid}, current effective uid is {current_uid}"
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prompt_group_confirmation(
    root: &KillTarget,
    members: &tree::ProcessTreeTarget,
    requirement: TreeConfirmation,
) -> std::io::Result<bool> {
    match requirement {
        TreeConfirmation::TypedWord(word) => eprint!(
            "Type {word} to terminate all {} processes in the group, or press Enter to cancel: ",
            members.len(),
        ),
        TreeConfirmation::ProtectedRoot => eprint!(
            "Protected root: type PID {} or process name {} to confirm: ",
            root.pid,
            sanitize(root.process_name_or_unknown()),
        ),
    }
    std::io::stderr().flush()?;

    let answer = read_confirmation_line(CONFIRMATION_INPUT_MAX_BYTES)?;
    Ok(tree_confirmation_matches(&answer, root, requirement))
}

/// The two facts the group confirmation established, carried together into
/// revalidation: which group the user actually saw, and whether the
/// protected-root confirmation was completed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy)]
struct ConfirmedGroupFacts {
    pgid: u32,
    confirmation: ScopedConfirmationFacts,
}

/// Revalidate the confirmed root and re-run every group gate against a fresh
/// scan, immediately before the freeze. The root must match exactly and must
/// still sit in the group the user confirmed; membership may have churned but
/// must re-pass the cap, unsafe-PID, and protection gates.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn revalidate_group_root_before_freeze<Ops, CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    confirmed_group: ConfirmedGroupFacts,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
    ops: &mut Ops,
) -> Result<KillTarget, tree::TreeKillOutcome>
where
    Ops: tree::TreeProcessOps,
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let fresh_root = if confirmed.ports.is_empty() {
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Group {
            root_pid: confirmed.pid,
            pgid: confirmed_group.pgid,
        });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        let root =
            revalidate_portless_tree_root(confirmed, &snapshot, &config.protected_processes)?;
        fresh_group_gates(&root, &snapshot, config, confirmed_group)?;
        root
    } else {
        let root = revalidate_cli_target(args, config, confirmed, collect_context, collect_ports)
            .map_err(|outcome| tree_outcome_from_termination(confirmed, outcome))?;
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Group {
            root_pid: root.pid,
            pgid: confirmed_group.pgid,
        });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        fresh_group_gates(&root, &snapshot, config, confirmed_group)?;
        root
    };
    Ok(fresh_root)
}

/// The fresh-scan gates for a group kill: the member set must still build, the root
/// must still sit in the confirmed group (otherwise the sweep would target a
/// member set the user never saw), and the pre-flight and root-protection
/// rules must re-pass.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fresh_group_gates(
    root: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    config: &Config,
    confirmed_group: ConfirmedGroupFacts,
) -> Result<(), tree::TreeKillOutcome> {
    let group = tree::plan_process_group(
        root.pid,
        snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_GROUP_PROCESSES,
    )
    .map_err(|error| match error {
        tree::GroupPlanError::RootMissing => tree::TreeKillOutcome::RootAlreadyExited,
        tree::GroupPlanError::GroupUnavailable => {
            tree::TreeKillOutcome::TargetChanged { pid: root.pid }
        }
    })?;
    if group.pgid() != confirmed_group.pgid {
        return Err(tree::TreeKillOutcome::TargetChanged { pid: root.pid });
    }
    tree::preflight_outcome(group.members())?;
    tree::root_protection_outcome(
        group.members(),
        confirmed_group.confirmation.protected_confirmed,
    )?;
    if confirmed_group.confirmation.skipped_prompt && !group_yes_skip_allowed(root, group.members())
    {
        return Err(tree::TreeKillOutcome::FreshConfirmationRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Only the freeze-first Unix tests build a target from a single row; the
    // Windows tree tests go through `entry_views` instead.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::model::PortEntryView;
    use crate::model::entry_views;
    use std::cell::RefCell;
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    use std::io::Write;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::net::{IpAddr, Ipv4Addr};
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::rc::Rc;

    use super::tree_outcome_from_termination;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::{
        GROUP_YES_SKIP_MAX_PROCESSES, TreeConfirmDecision, TreeKillSeams, group_confirmation,
        kill_target_from_tree_info, run_group_kill_with, run_tree_kill_with, tree_confirmation,
    };
    use crate::cli::ExitReason;
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    use crate::cli::KillArgs;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::cli::test_support::entry_with_pid;
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    use crate::cli::test_support::{entry, no_context};
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    use crate::config::Config;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::model::{
        ChildProcess, ChildProcessSnapshot, PortEntry, ProcessContext, SocketState,
    };
    use crate::model::{PermissionStatus, Platform, Protocol};
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    use crate::observation::{
        EvidenceGapCode, EvidenceImpact, MetadataProfile, NetworkSnapshot, OwnerCompleteness,
        SnapshotCompleteness,
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::process::KillMode;
    use crate::process::KillTarget;
    use crate::process::TerminationOutcome;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::tree::{ProcessTreeTarget, TreeProcessInfo, TreeProcessOps, TreeSignalResult};
    #[cfg(windows)]
    use crate::windows_tree::WindowsTreeTerminationState;

    #[test]
    fn already_exited_single_outcome_maps_to_root_already_exited() {
        let confirmed = KillTarget {
            pid: 18_422,
            process_name: Some("node".to_owned()),
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            protected: false,
            system_process: false,
            ports: Vec::new(),
            owner_uid: Some(1_000),
            process_start_time_marker: None,
            child_count: 0,
            children_truncated: false,
        };

        let refusal = tree_outcome_from_termination(&confirmed, TerminationOutcome::AlreadyExited);
        assert_eq!(refusal, crate::tree::TreeKillOutcome::RootAlreadyExited);
        #[cfg(windows)]
        assert_eq!(
            crate::windows_tree::WindowsTreeKillOutcome::from_precommit_outcome(refusal.clone()),
            crate::windows_tree::WindowsTreeKillOutcome::Refused(refusal),
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    fn locally_incomplete_kill_snapshot() -> NetworkSnapshot {
        use crate::collector::Collector;

        let mut snapshot = crate::collector::FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake snapshot collects");
        snapshot.completeness = SnapshotCompleteness::Complete;
        snapshot.owner_completeness = OwnerCompleteness::Complete;
        snapshot
            .evidence_gaps
            .retain(|gap| gap.impact != EvidenceImpact::SocketSet);
        for socket in &mut snapshot.sockets {
            socket.owner_completeness = OwnerCompleteness::Complete;
        }

        snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture has port 3000")
            .owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
                .expect("one reason fits");
        snapshot
    }

    #[cfg(windows)]
    fn confirm_windows_tree_prompt(
        _target: &KillTarget,
        _tree: &crate::tree::ProcessTreeTarget,
        _requirement: super::TreeConfirmation,
    ) -> std::io::Result<bool> {
        std::io::sink().write_all(&[])?;
        Ok(true)
    }

    #[cfg(windows)]
    fn panic_windows_tree_execute(
        _root: &KillTarget,
        _protected: &[String],
        _confirmed: bool,
        _skipped: bool,
    ) -> crate::windows_tree::WindowsTreeKillOutcome {
        panic!("authoritative refusal must precede Job Object assignment")
    }

    #[cfg(windows)]
    #[test]
    fn windows_tree_authority_refusal_precedes_job_assignment() {
        let snapshot = locally_incomplete_kill_snapshot();
        let process_snapshot = vec![crate::tree::TreeProcessInfo {
            pid: 18_422,
            parent_pid: Some(500),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("node.exe".to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::windows(55).ok(),
            owner_uid: None,
            process_group: None,
        }];

        let reason = super::run_windows_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: true,
            },
            &Config::default(),
            &entry_views(&[entry(3000)]),
            crate::process::KillMode::Terminate,
            super::WindowsTreeKillSeams {
                collect_tree: || Ok(process_snapshot.clone()),
                collect_context: no_context,
                prompt: confirm_windows_tree_prompt,
                collect_kill_ports: || {
                    crate::collector::kill_ports_from_snapshot(&snapshot, Some(18_422), None)
                },
                collect_ports: || panic!("refusal must not visibility-poll ports"),
                prepare_root: |_pid| -> Result<u32, TerminationOutcome> {
                    panic!("PID mode must preserve its existing preparation path")
                },
                execute: panic_windows_tree_execute,
            },
        );

        assert_eq!(reason, ExitReason::Failure);
    }

    #[cfg(windows)]
    #[test]
    fn windows_port_tree_root_exit_during_preparation_is_no_match() {
        let process_snapshot = vec![crate::tree::TreeProcessInfo {
            pid: 18_422,
            parent_pid: Some(500),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("node".to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::windows(55).ok(),
            owner_uid: None,
            process_group: None,
        }];
        let events = RefCell::new(Vec::new());

        let reason = super::run_windows_tree_kill_with(
            &KillArgs {
                pid: None,
                port: Some(3000),
                force: false,
                yes: true,
                tree: true,
            },
            &Config::default(),
            &entry_views(&[entry(3000)]),
            crate::process::KillMode::Terminate,
            super::WindowsTreeKillSeams {
                collect_tree: || Ok(process_snapshot.clone()),
                collect_context: no_context,
                prompt: confirm_windows_tree_prompt,
                collect_kill_ports: || {
                    panic!("root preparation refusal must precede final endpoint collection")
                },
                collect_ports: || {
                    events.borrow_mut().push("visibility");
                    Ok(Vec::new())
                },
                prepare_root: |pid| -> Result<u32, TerminationOutcome> {
                    assert_eq!(pid, 18_422);
                    events.borrow_mut().push("prepare");
                    Err(TerminationOutcome::AlreadyExited)
                },
                execute: panic_windows_tree_execute,
            },
        );

        assert_eq!(reason, ExitReason::NoMatch);
        assert_eq!(*events.borrow(), ["prepare", "visibility"]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_port_owner_move_after_root_prepare_never_commits_job() {
        let process_snapshot = vec![crate::tree::TreeProcessInfo {
            pid: 18_422,
            parent_pid: Some(500),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("node".to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::windows(55).ok(),
            owner_uid: None,
            process_group: None,
        }];
        let moved = vec![crate::cli::test_support::entry_with_pid(
            3000,
            Some(29_999),
            Protocol::Tcp,
            "replacement",
        )];
        let events = RefCell::new(Vec::new());
        let context = || crate::model::ProcessContext {
            owner_uid: None,
            process_start_time_marker: crate::observation::ProcessStartMarker::windows(55).ok(),
            children: crate::model::ChildProcessSnapshot::default(),
            docker: None,
        };

        let reason = super::run_windows_tree_kill_with(
            &KillArgs {
                pid: None,
                port: Some(3000),
                force: false,
                yes: true,
                tree: true,
            },
            &Config::default(),
            &entry_views(&[entry(3000)]),
            crate::process::KillMode::Terminate,
            super::WindowsTreeKillSeams {
                collect_tree: || Ok(process_snapshot.clone()),
                collect_context: |_pid| context(),
                prompt: confirm_windows_tree_prompt,
                collect_kill_ports: || {
                    events.borrow_mut().push("collect");
                    Ok(moved.clone())
                },
                collect_ports: || panic!("refusal must not visibility-poll ports"),
                prepare_root: |pid| {
                    assert_eq!(pid, 18_422);
                    events.borrow_mut().push("prepare");
                    Ok::<u32, TerminationOutcome>(pid)
                },
                execute: |_root: &KillTarget,
                          _protected: &[String],
                          _confirmed: bool,
                          _skipped: bool| {
                    events.borrow_mut().push("commit");
                    panic!("moved endpoint must prevent Job Object commit")
                },
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert_eq!(*events.borrow(), ["prepare", "collect"]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_post_commit_protected_issue_exits_with_protected_code() {
        let root = KillTarget {
            pid: 100,
            process_name: Some("node.exe".to_owned()),
            platform: Platform::Windows,
            permission: PermissionStatus::Full,
            protected: false,
            system_process: false,
            ports: Vec::new(),
            owner_uid: None,
            process_start_time_marker: crate::observation::ProcessStartMarker::windows(100).ok(),
            child_count: 0,
            children_truncated: false,
        };
        let report = crate::windows_tree::WindowsTreeKillReport {
            total: 1,
            job_terminated_pids: vec![100],
            already_exited_pids: Vec::new(),
            not_terminated: vec![101],
            termination_state: WindowsTreeTerminationState::Partial,
            post_commit_issue: Some(
                crate::windows_tree::WindowsTreePostCommitIssue::ProtectedDescendant {
                    pid: 101,
                    name: Some("lsass.exe".to_owned()),
                },
            ),
            secondary_post_commit_issue: Some(
                crate::windows_tree::WindowsTreePostCommitIssue::SnapshotFailed(
                    "freezing committed Job Object failed: freeze failed".to_owned(),
                ),
            ),
            cleanup_issue: Some(
                crate::windows_tree::WindowsTreeCleanupIssue::WithheldJobThawFailed(
                    "thaw failed".to_owned(),
                ),
            ),
        };
        let mut collect_ports = || Ok(Vec::new());

        let reason = super::map_windows_tree_completed_outcome(&root, &report, &mut collect_ports);

        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
    }

    #[cfg(windows)]
    #[test]
    fn windows_post_commit_warning_refusal_is_visible_and_fails() {
        let issue = crate::windows_tree::WindowsTreePostCommitIssue::FreshConfirmationRequired;

        let text = super::windows_post_commit_issue_text(&issue);
        let reason = super::windows_post_commit_issue_exit_reason(&issue);

        assert!(text.contains("gained warnings after --yes"));
        assert_eq!(reason, ExitReason::Failure);
    }

    #[cfg(windows)]
    #[test]
    fn windows_post_commit_protected_root_requires_confirmation() {
        let issue = crate::windows_tree::WindowsTreePostCommitIssue::ProtectedRoot {
            pid: 100,
            name: Some("lsass.exe".to_owned()),
        };

        let text = super::windows_post_commit_issue_text(&issue);
        let reason = super::windows_post_commit_issue_exit_reason(&issue);

        assert!(text.contains("root PID 100"));
        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
    }

    #[cfg(windows)]
    #[test]
    fn windows_tree_success_polls_post_kill_visibility() {
        let root = KillTarget {
            pid: 100,
            process_name: Some("node.exe".to_owned()),
            platform: Platform::Windows,
            permission: PermissionStatus::Full,
            protected: false,
            system_process: false,
            ports: vec![crate::process::KillTargetPort {
                protocol: Protocol::Tcp,
                local_addr: "127.0.0.1".parse().expect("test address"),
                local_port: 3000,
                ipv6_scope: None,
            }],
            owner_uid: None,
            process_start_time_marker: crate::observation::ProcessStartMarker::windows(100).ok(),
            child_count: 0,
            children_truncated: false,
        };
        let report = crate::windows_tree::WindowsTreeKillReport {
            total: 1,
            job_terminated_pids: vec![100],
            already_exited_pids: Vec::new(),
            not_terminated: Vec::new(),
            termination_state: WindowsTreeTerminationState::Complete,
            post_commit_issue: None,
            secondary_post_commit_issue: None,
            cleanup_issue: None,
        };
        let mut visibility_polls = 0;
        let mut collect_ports = || {
            visibility_polls += 1;
            Ok(Vec::new())
        };

        let reason = super::map_windows_tree_completed_outcome(&root, &report, &mut collect_ports);

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(visibility_polls, 1);
    }

    #[cfg(windows)]
    #[test]
    fn windows_partial_report_names_every_outcome_pid() {
        let root = KillTarget {
            pid: 100,
            process_name: Some("node.exe".to_owned()),
            platform: Platform::Windows,
            permission: PermissionStatus::Full,
            protected: false,
            system_process: false,
            ports: Vec::new(),
            owner_uid: None,
            process_start_time_marker: crate::observation::ProcessStartMarker::windows(100).ok(),
            child_count: 0,
            children_truncated: false,
        };
        let report = crate::windows_tree::WindowsTreeKillReport {
            total: 3,
            job_terminated_pids: Vec::new(),
            already_exited_pids: vec![102],
            not_terminated: vec![100, 103],
            termination_state: WindowsTreeTerminationState::Withheld,
            post_commit_issue: Some(
                crate::windows_tree::WindowsTreePostCommitIssue::ProtectedDescendant {
                    pid: 103,
                    name: Some("lsass.exe".to_owned()),
                },
            ),
            secondary_post_commit_issue: Some(
                crate::windows_tree::WindowsTreePostCommitIssue::SnapshotFailed(
                    "freezing committed Job Object failed: freeze failed".to_owned(),
                ),
            ),
            cleanup_issue: Some(
                crate::windows_tree::WindowsTreeCleanupIssue::WithheldJobThawFailed(
                    "thaw failed".to_owned(),
                ),
            ),
        };

        let text = super::windows_tree_partial_report_text(&root, &report);

        assert!(text.contains("job-terminated 0 of 3"), "{text}");
        assert!(text.contains("already exited (PIDs: 102)"), "{text}");
        assert!(
            text.contains("not confirmed terminated: 100, 103"),
            "{text}"
        );
        assert!(
            text.contains("protected descendant PID 103 (lsass.exe)"),
            "{text}"
        );
        assert!(
            text.contains("secondary post-commit issue: enumerating the Windows process tree failed after commit: freezing committed Job Object failed: freeze failed"),
            "{text}"
        );
        assert!(
            text.contains("strict tree closure could not be established"),
            "{text}"
        );
        assert!(
            text.contains(
                "cleanup issue: thawing the withheld Windows Job Object failed: thaw failed"
            ),
            "{text}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn failed_windows_job_mapping_prints_partial_report_and_refreshes_ports() {
        let root = KillTarget {
            pid: 100,
            process_name: Some("node.exe".to_owned()),
            platform: Platform::Windows,
            permission: PermissionStatus::Full,
            protected: false,
            system_process: false,
            ports: vec![crate::process::KillTargetPort {
                protocol: Protocol::Tcp,
                local_addr: "127.0.0.1".parse().expect("test address"),
                local_port: 3000,
                ipv6_scope: None,
            }],
            owner_uid: None,
            process_start_time_marker: crate::observation::ProcessStartMarker::windows(100).ok(),
            child_count: 0,
            children_truncated: false,
        };
        let outcome = crate::windows_tree::WindowsTreeKillOutcome::JobTerminateFailed {
            error: "job failed".to_owned(),
            report: Box::new(crate::windows_tree::WindowsTreeKillReport {
                total: 2,
                job_terminated_pids: Vec::new(),
                already_exited_pids: vec![102],
                not_terminated: vec![100],
                termination_state: WindowsTreeTerminationState::Partial,
                post_commit_issue: None,
                secondary_post_commit_issue: None,
                cleanup_issue: Some(
                    crate::windows_tree::WindowsTreeCleanupIssue::FailedTerminationThawFailed(
                        "thaw failed".to_owned(),
                    ),
                ),
            }),
        };
        let mut refreshes = 0;
        let mut collect_ports = || {
            refreshes += 1;
            Ok(Vec::new())
        };
        let mut stderr = Vec::new();

        let reason = super::map_windows_tree_system_failure(
            &root,
            &outcome,
            &mut collect_ports,
            &mut stderr,
        );
        let text = String::from_utf8(stderr).expect("diagnostic must be UTF-8");

        assert_eq!(reason, ExitReason::Failure);
        assert_eq!(refreshes, 1);
        assert!(
            text.contains("TerminateJobObject failed: job failed"),
            "{text}"
        );
        assert!(text.contains("already exited (PIDs: 102)"), "{text}");
        assert!(text.contains("not confirmed terminated: 100"), "{text}");
        assert!(
            text.contains("cleanup issue: thawing the Windows Job Object after TerminateJobObject failed: thaw failed"),
            "{text}"
        );
        assert!(
            text.contains("confirmed target ports are no longer visible"),
            "{text}"
        );
    }

    /// Tree ops that allow the preview read but fail the test if the pipeline is
    /// ever reached: used to prove refusals happen before any process is touched.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct PreviewOnlyTreeOps(Vec<TreeProcessInfo>);

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl TreeProcessOps for PreviewOnlyTreeOps {
        fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
            Ok(self.0.clone())
        }

        fn stop(&mut self, _pid: u32) -> TreeSignalResult {
            panic!("no process may be stopped for an unresolved root")
        }

        fn cont(&mut self, _pid: u32) -> TreeSignalResult {
            panic!("no process may be continued for an unresolved root")
        }

        fn prepare_delivery(
            &mut self,
            _pid: u32,
            _verified_start_marker: Option<crate::observation::ProcessStartMarker>,
        ) -> TreeSignalResult {
            panic!("no pidfd may be opened for an unresolved root")
        }

        fn deliver(&mut self, _pid: u32, _mode: KillMode) -> TreeSignalResult {
            panic!("no signal may be sent for an unresolved root")
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RecordingTreeEvent {
        Pin(u32),
        CollectPorts,
        Stop(u32),
        Deliver(u32),
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct RecordingTreeOps {
        snapshots: Vec<Vec<TreeProcessInfo>>,
        next: usize,
        stops: Vec<u32>,
        events: Rc<RefCell<Vec<RecordingTreeEvent>>>,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl RecordingTreeOps {
        fn new(snapshots: Vec<Vec<TreeProcessInfo>>) -> Self {
            Self {
                snapshots,
                next: 0,
                stops: Vec::new(),
                events: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl TreeProcessOps for RecordingTreeOps {
        fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
            let index = self.next.min(self.snapshots.len().saturating_sub(1));
            self.next += 1;
            Ok(self.snapshots.get(index).cloned().unwrap_or_default())
        }

        fn pin_root_for_revalidation(&mut self, pid: u32) -> TreeSignalResult {
            self.events.borrow_mut().push(RecordingTreeEvent::Pin(pid));
            TreeSignalResult::Delivered
        }

        fn stop(&mut self, pid: u32) -> TreeSignalResult {
            self.stops.push(pid);
            self.events.borrow_mut().push(RecordingTreeEvent::Stop(pid));
            TreeSignalResult::Delivered
        }

        fn cont(&mut self, _pid: u32) -> TreeSignalResult {
            TreeSignalResult::Delivered
        }

        fn prepare_delivery(
            &mut self,
            _pid: u32,
            _verified_start_marker: Option<crate::observation::ProcessStartMarker>,
        ) -> TreeSignalResult {
            TreeSignalResult::Delivered
        }

        fn deliver(&mut self, pid: u32, _mode: KillMode) -> TreeSignalResult {
            self.events
                .borrow_mut()
                .push(RecordingTreeEvent::Deliver(pid));
            TreeSignalResult::Delivered
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn kill_pid_tree(pid: u32) -> KillArgs {
        KillArgs {
            pid: Some(pid),
            port: None,
            force: false,
            yes: false,
            tree: true,
            group: false,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn kill_pid_tree_yes(pid: u32) -> KillArgs {
        KillArgs {
            pid: Some(pid),
            port: None,
            force: false,
            yes: true,
            tree: true,
            group: false,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_kill_of_missing_pid_reports_no_match_without_touching_processes() {
        // The PID owns no visible port and is absent from the tree snapshot, so
        // tree kill refuses before freeze, prompt, or signal delivery.
        let reason = run_tree_kill_with(
            &kill_pid_tree(4_242),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut PreviewOnlyTreeOps(Vec::new()),
            TreeKillSeams {
                collect_context: no_context,
                prompt: |_target: &KillTarget, _tree: &ProcessTreeTarget, _requirement| {
                    panic!("unresolved root must not prompt")
                },
                collect_kill_ports: || panic!("unresolved root must not re-collect ports"),
                collect_ports: || panic!("unresolved root must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::NoMatch);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tree_info(pid: u32, parent_pid: Option<u32>, name: &str) -> TreeProcessInfo {
        TreeProcessInfo {
            pid,
            parent_pid,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some(name.to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::linux(u64::from(pid)).ok(),
            owner_uid: None,
            process_group: None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tree_info_without_start_marker(
        pid: u32,
        parent_pid: Option<u32>,
        name: &str,
    ) -> TreeProcessInfo {
        TreeProcessInfo {
            start_time_marker: None,
            ..tree_info(pid, parent_pid, name)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tree_info_owned_by_other_uid(
        pid: u32,
        parent_pid: Option<u32>,
        name: &str,
    ) -> TreeProcessInfo {
        TreeProcessInfo {
            owner_uid: Some(crate::process::current_user_id().saturating_add(1)),
            ..tree_info(pid, parent_pid, name)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tree_target(infos: &[TreeProcessInfo], protected_names: &[String]) -> ProcessTreeTarget {
        crate::tree::plan_process_tree(100, infos, protected_names, Platform::Linux, 256)
            .expect("test tree root must be present")
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn confirm_tree_prompt(
        _target: &KillTarget,
        _tree: &ProcessTreeTarget,
        _requirement: super::TreeConfirmation,
    ) -> std::io::Result<bool> {
        std::io::sink().write_all(&[])?;
        Ok(true)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn panic_tree_prompt(
        _target: &KillTarget,
        _tree: &ProcessTreeTarget,
        _requirement: super::TreeConfirmation,
    ) -> std::io::Result<bool> {
        panic!("tree prompt must not be reached")
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_gates_yes_and_protected_roots() {
        // This is the --yes safety table: --yes may only skip the prompt on a
        // tree with nothing to warn about, and can never authorize a protected
        // root.
        let clean = tree_target(&[tree_info(100, Some(500), "node")], &[]);
        let clean_root = kill_target_from_tree_info(&tree_info(100, Some(500), "node"), &[]);
        assert_eq!(
            tree_confirmation(&clean_root, &clean, KillMode::Terminate, true),
            TreeConfirmDecision::Skip,
        );
        assert_eq!(
            tree_confirmation(&clean_root, &clean, KillMode::Terminate, false),
            TreeConfirmDecision::PromptWord("tree"),
        );
        assert_eq!(
            tree_confirmation(&clean_root, &clean, KillMode::Force, false),
            TreeConfirmDecision::PromptWord("force"),
        );

        // A system/service member is a warning, so --yes downgrades to the
        // typed prompt instead of skipping it.
        let with_system = tree_target(
            &[
                tree_info(100, Some(500), "node"),
                tree_info(101, Some(100), "systemd"),
            ],
            &[],
        );
        assert_eq!(
            tree_confirmation(&clean_root, &with_system, KillMode::Terminate, true),
            TreeConfirmDecision::PromptWord("tree"),
        );

        // A member owned by another uid is also a warning, so --yes downgrades
        // to the typed prompt instead of skipping it.
        let with_other_uid = tree_target(
            &[
                tree_info(100, Some(500), "node"),
                tree_info_owned_by_other_uid(101, Some(100), "worker"),
            ],
            &[],
        );
        assert_eq!(
            tree_confirmation(&clean_root, &with_other_uid, KillMode::Terminate, true),
            TreeConfirmDecision::PromptWord("tree"),
        );

        // A protected root keeps the protected typed confirmation, and --yes
        // refuses outright rather than silently skipping it.
        let protected_root = tree_target(
            &[tree_info(100, Some(500), "postgres")],
            &["postgres".to_owned()],
        );
        let protected_root_target = kill_target_from_tree_info(
            &tree_info(100, Some(500), "postgres"),
            &["postgres".to_owned()],
        );
        assert_eq!(
            tree_confirmation(
                &protected_root_target,
                &protected_root,
                KillMode::Terminate,
                true
            ),
            TreeConfirmDecision::RefuseProtectedYes,
        );
        assert_eq!(
            tree_confirmation(
                &protected_root_target,
                &protected_root,
                KillMode::Terminate,
                false
            ),
            TreeConfirmDecision::PromptProtectedThenWord("tree"),
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_banner_child_warning_uses_tree_scope() {
        // Feed the rewrite the *real* warning_lines() output, not a copied
        // literal: if the single-kill wording in process.rs ever drifts, the
        // suffix rewrite silently stops matching, and only a test wired to the
        // genuine source can catch that.
        let row = entry(3000);
        let context = ProcessContext {
            children: ChildProcessSnapshot {
                children: vec![
                    ChildProcess {
                        pid: 18_430,
                        process_name: None,
                    },
                    ChildProcess {
                        pid: 18_431,
                        process_name: None,
                    },
                ],
                truncated: false,
            },
            ..ProcessContext::default()
        };
        let target = KillTarget::from_entries(18_422, [PortEntryView::from(&row)], Some(&context));
        let warning = target
            .warning_lines()
            .into_iter()
            .find(|line| line.starts_with("target has"))
            .expect("a target with children must warn about them");

        assert_eq!(
            crate::process::tree_scope_warning_text(&warning),
            "target has 2 direct child process(es); tree kill targets the bounded descendant tree shown above",
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn port_selected_tree_pins_old_root_before_endpoint_move_and_sends_no_signal() {
        let rows = vec![entry(3000)];
        let preview = vec![tree_info(18_422, Some(500), "node")];
        let mut ops = RecordingTreeOps::new(vec![preview]);
        let events = Rc::clone(&ops.events);
        let fresh_rows = vec![entry_with_pid(
            3000,
            Some(29_999),
            Protocol::Tcp,
            "replacement",
        )];

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: None,
                port: Some(3000),
                force: false,
                yes: false,
                tree: true,
                group: false,
            },
            &Config::default(),
            &entry_views(&rows),
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_kill_ports: || {
                    events.borrow_mut().push(RecordingTreeEvent::CollectPorts);
                    Ok(fresh_rows.clone())
                },
                collect_ports: || Ok(Vec::new()),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert_eq!(
            &*events.borrow(),
            &[
                RecordingTreeEvent::Pin(18_422),
                RecordingTreeEvent::CollectPorts,
            ],
            "the old root handle must be prepared before final endpoint ownership collection",
        );
        assert!(ops.stops.is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn portless_tree_root_missing_start_marker_refuses_before_any_stop() {
        // Real Linux/macOS tree snapshots fail closed before producing this row,
        // but the shared CLI seam still has to enforce the identity contract:
        // a portless PID root without a start marker is not safe to freeze.
        let snapshot = vec![tree_info_without_start_marker(18_422, Some(500), "node")];
        let mut ops = RecordingTreeOps::new(vec![snapshot]);
        let events = Rc::clone(&ops.events);

        let reason = run_tree_kill_with(
            &kill_pid_tree(18_422),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_kill_ports: || panic!("portless tree root must not re-collect ports"),
                collect_ports: || panic!("portless tree root must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert_eq!(&*events.borrow(), &[RecordingTreeEvent::Pin(18_422)]);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_losing_readable_owner_during_revalidation_exits_permission_denied() {
        let rows = vec![entry(3000)];
        let preview = vec![tree_info(18_422, Some(500), "node")];
        let mut ops = RecordingTreeOps::new(vec![preview]);
        let events = Rc::clone(&ops.events);
        let fresh_rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: true,
                group: false,
            },
            &Config::default(),
            &entry_views(&rows),
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_kill_ports: || {
                    events.borrow_mut().push(RecordingTreeEvent::CollectPorts);
                    Ok(fresh_rows.clone())
                },
                collect_ports: || Ok(Vec::new()),
            },
        );

        assert_eq!(reason, ExitReason::PermissionDenied);
        assert_eq!(
            &*events.borrow(),
            &[
                RecordingTreeEvent::Pin(18_422),
                RecordingTreeEvent::CollectPorts,
            ],
        );
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_authority_refusal_has_zero_stop_or_delivery() {
        let snapshot = locally_incomplete_kill_snapshot();
        let rows = vec![entry(3000)];
        let preview = vec![tree_info(18_422, Some(500), "node")];
        let mut ops = RecordingTreeOps::new(vec![preview]);

        let reason = run_tree_kill_with(
            &kill_pid_tree(18_422),
            &Config::default(),
            &entry_views(&rows),
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_kill_ports: || {
                    crate::collector::kill_ports_from_snapshot(&snapshot, Some(18_422), None)
                },
                collect_ports: || panic!("refusal must not visibility-poll ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty());
        assert!(
            !ops.events
                .borrow()
                .iter()
                .any(|event| matches!(event, RecordingTreeEvent::Deliver(_)))
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fresh_tree_cap_preflight_refuses_before_any_stop() {
        let rows = vec![entry(3000)];
        let mut over_cap = vec![tree_info(18_422, Some(500), "node")];
        let max_tree_processes =
            u32::try_from(crate::tree::MAX_TREE_PROCESSES).expect("test cap must fit u32");
        for pid in 30_000..=(30_000 + max_tree_processes) {
            over_cap.push(tree_info(pid, Some(18_422), "child"));
        }
        let preview = vec![tree_info(18_422, Some(500), "node")];
        let mut ops = RecordingTreeOps::new(vec![preview, over_cap]);

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: true,
                group: false,
            },
            &Config::default(),
            &entry_views(&rows),
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_kill_ports: || Ok(rows.clone()),
                collect_ports: || Ok(rows.clone()),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fresh_tree_warning_after_yes_skip_refuses_before_any_stop() {
        let clean = vec![tree_info(18_422, Some(500), "node")];
        let warned = vec![
            tree_info(18_422, Some(500), "node"),
            TreeProcessInfo {
                pid: 18_423,
                parent_pid: Some(18_422),
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: None,
                start_time_marker: crate::observation::ProcessStartMarker::linux(18_423).ok(),
                owner_uid: None,
                process_group: None,
            },
        ];
        let mut ops = RecordingTreeOps::new(vec![clean, warned]);

        let reason = run_tree_kill_with(
            &kill_pid_tree_yes(18_422),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_kill_ports: || panic!("portless tree root must not re-collect ports"),
                collect_ports: || panic!("portless tree root must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn protected_tree_descendant_refuses_before_prompt_or_stop_even_with_yes() {
        let rows = vec![entry(3000)];
        let snapshot = vec![
            tree_info(18_422, Some(500), "node"),
            tree_info(18_423, Some(18_422), "postgres"),
        ];
        let config = Config {
            protected_processes: vec!["postgres".to_owned()],
            ..Config::default()
        };

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: true,
                tree: true,
                group: false,
            },
            &config,
            &entry_views(&rows),
            KillMode::Terminate,
            &mut PreviewOnlyTreeOps(snapshot),
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_kill_ports: || panic!("protected descendant must not re-collect ports"),
                collect_ports: || panic!("protected descendant must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
    }

    /// A port row with no readable process name, so the row policy cannot mark
    /// the root protected — the tree scan is the only reader that can.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn nameless_row(port: u16, pid: u32) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid: Some(pid),
            process_name: None,
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Partial,
            process_identity: Some(crate::observation::ProcessIdentity {
                pid,
                start_marker: crate::observation::ProcessStartMarker::linux(55)
                    .expect("test marker is nonzero"),
            }),
            ipv6_scope: None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn root_turning_protected_between_confirmation_and_freeze_refuses_with_exit_6() {
        // The confirmed row has no readable name, so identity revalidation
        // cannot compare names. Between confirmation and execution the root
        // execs into a protected name — same PID, same start marker. The fresh
        // root-protection gate must refuse before any stop.
        let rows = vec![nameless_row(3000, 18_422)];
        let confirmation_snapshot = vec![tree_info(18_422, Some(500), "node")];
        let execed_snapshot = vec![TreeProcessInfo {
            pid: 18_422,
            parent_pid: Some(500),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("postgres".to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::linux(18_422).ok(),
            owner_uid: None,
            process_group: None,
        }];
        let config = Config {
            protected_processes: vec!["postgres".to_owned()],
            ..Config::default()
        };
        let mut ops = RecordingTreeOps::new(vec![confirmation_snapshot, execed_snapshot]);

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: true,
                group: false,
            },
            &config,
            &entry_views(&rows),
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_kill_ports: || Ok(rows.clone()),
                collect_ports: || Ok(rows.clone()),
            },
        );

        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn completed_protected_confirmation_passes_the_root_protection_gate() {
        // The inverse of the guard: a protected root whose two-step
        // confirmation was completed must execute, not be re-refused.
        // `cli::run` marks entries against the protected list before resolving
        // targets, so the test input must arrive marked the same way.
        let mut rows = vec![entry_with_pid(
            3000,
            Some(18_422),
            Protocol::Tcp,
            "postgres",
        )];
        crate::protection::mark_protected(&mut rows, &["postgres".to_owned()]);
        let snapshot = vec![TreeProcessInfo {
            pid: 18_422,
            parent_pid: Some(500),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("postgres".to_owned()),
            // Matches the confirmed context marker from `no_context`.
            start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            owner_uid: None,
            process_group: None,
        }];
        let config = Config {
            protected_processes: vec!["postgres".to_owned()],
            ..Config::default()
        };
        let mut ops = RecordingTreeOps::new(vec![snapshot]);
        let mut prompts = 0;
        let mut authority_collections = 0;
        let mut visibility_polls = 0;

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: true,
                group: false,
            },
            &config,
            &entry_views(&rows),
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: |_target: &KillTarget, _tree: &ProcessTreeTarget, _requirement| {
                    prompts += 1;
                    Ok(true)
                },
                collect_kill_ports: || {
                    authority_collections += 1;
                    Ok(rows.clone())
                },
                collect_ports: || {
                    visibility_polls += 1;
                    Ok(Vec::new())
                },
            },
        );

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(prompts, 2, "protected root asks for PID/name and the word");
        assert_eq!(authority_collections, 1);
        assert_eq!(visibility_polls, 1);
        assert_eq!(ops.stops, vec![18_422]);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn grouped_info(pid: u32, parent_pid: Option<u32>, name: &str, group: u32) -> TreeProcessInfo {
        TreeProcessInfo {
            owner_uid: None,
            process_group: Some(group),
            ..tree_info(pid, parent_pid, name)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn group_target(
        infos: &[TreeProcessInfo],
        root_pid: u32,
        protected_names: &[String],
    ) -> crate::tree::ProcessGroupTarget {
        crate::tree::plan_process_group(root_pid, infos, protected_names, Platform::Linux, 512)
            .expect("test group root must be present")
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn kill_pid_group(pid: u32, yes: bool) -> KillArgs {
        KillArgs {
            pid: Some(pid),
            port: None,
            force: false,
            yes,
            tree: false,
            group: true,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn kill_port_group(port: u16) -> KillArgs {
        KillArgs {
            pid: None,
            port: Some(port),
            force: false,
            yes: false,
            tree: false,
            group: true,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_confirmation_gates_yes_by_size_warnings_and_protection() {
        let root = kill_target_from_tree_info(&grouped_info(100, Some(500), "node", 42), &[]);

        // Tiny, warning-free group: --yes may skip, everything else prompts
        // for the scope word ("group", or "force" under --force).
        let tiny = group_target(&[grouped_info(100, Some(500), "node", 42)], 100, &[]);
        assert_eq!(
            group_confirmation(&root, &tiny, KillMode::Terminate, true),
            TreeConfirmDecision::Skip,
        );
        assert_eq!(
            group_confirmation(&root, &tiny, KillMode::Terminate, false),
            TreeConfirmDecision::PromptWord("group"),
        );
        assert_eq!(
            group_confirmation(&root, &tiny, KillMode::Force, false),
            TreeConfirmDecision::PromptWord("force"),
        );

        // One member past the tiny cap: --yes falls back to the typed word. A
        // group has no structural tie to the target, so size alone is a risk.
        let mut big_infos = vec![grouped_info(100, Some(500), "node", 42)];
        for pid in 0..u32::try_from(GROUP_YES_SKIP_MAX_PROCESSES).expect("cap fits u32") {
            big_infos.push(grouped_info(9_000 + pid, Some(500), "worker", 42));
        }
        let big = group_target(&big_infos, 100, &[]);
        assert!(big.members().len() > GROUP_YES_SKIP_MAX_PROCESSES);
        assert_eq!(
            group_confirmation(&root, &big, KillMode::Terminate, true),
            TreeConfirmDecision::PromptWord("group"),
        );

        // A system/service member is a warning: --yes prompts.
        let with_system = group_target(
            &[
                grouped_info(100, Some(500), "node", 42),
                grouped_info(101, Some(1), "systemd", 42),
            ],
            100,
            &[],
        );
        assert_eq!(
            group_confirmation(&root, &with_system, KillMode::Terminate, true),
            TreeConfirmDecision::PromptWord("group"),
        );

        // A different-uid group member is a warning: --yes prompts.
        let with_other_uid = group_target(
            &[
                grouped_info(100, Some(500), "node", 42),
                TreeProcessInfo {
                    process_group: Some(42),
                    ..tree_info_owned_by_other_uid(101, Some(500), "worker")
                },
            ],
            100,
            &[],
        );
        assert_eq!(
            group_confirmation(&root, &with_other_uid, KillMode::Terminate, true),
            TreeConfirmDecision::PromptWord("group"),
        );

        // A protected root keeps the two-step confirmation; --yes refuses.
        let protected_names = vec!["postgres".to_owned()];
        let protected_root_target = kill_target_from_tree_info(
            &grouped_info(100, Some(500), "postgres", 42),
            &protected_names,
        );
        let protected = group_target(
            &[grouped_info(100, Some(500), "postgres", 42)],
            100,
            &protected_names,
        );
        assert_eq!(
            group_confirmation(
                &protected_root_target,
                &protected,
                KillMode::Terminate,
                true
            ),
            TreeConfirmDecision::RefuseProtectedYes,
        );
        assert_eq!(
            group_confirmation(
                &protected_root_target,
                &protected,
                KillMode::Terminate,
                false
            ),
            TreeConfirmDecision::PromptProtectedThenWord("group"),
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn protected_group_member_refuses_before_prompt_or_stop_even_with_yes() {
        let snapshot = vec![
            grouped_info(18_422, Some(500), "node", 42),
            grouped_info(18_423, Some(1), "postgres", 42),
        ];
        let config = Config {
            protected_processes: vec!["postgres".to_owned()],
            ..Config::default()
        };

        let reason = run_group_kill_with(
            &kill_pid_group(18_422, true),
            &config,
            &[],
            KillMode::Terminate,
            &mut PreviewOnlyTreeOps(snapshot),
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_kill_ports: || panic!("protected member must not re-collect ports"),
                collect_ports: || panic!("protected member must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_kill_refuses_kernel_domain_roots_without_touching_processes() {
        // The root exists but has no targetable group (pgid 0 maps to None):
        // refuse before any prompt, freeze, or signal.
        let snapshot = vec![tree_info(18_422, Some(500), "node")];

        let reason = run_group_kill_with(
            &kill_pid_group(18_422, false),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut PreviewOnlyTreeOps(snapshot),
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_kill_ports: || panic!("untargetable group must not re-collect ports"),
                collect_ports: || panic!("untargetable group must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_root_moving_groups_between_confirmation_and_freeze_refuses_before_any_stop() {
        // The user confirmed group 42; by execution time the root sits in 77.
        // Killing group 77 was never shown to the user, so the fresh gate must
        // refuse with nothing stopped.
        let confirmation_snapshot = vec![
            grouped_info(18_422, Some(500), "node", 42),
            grouped_info(17_000, Some(1), "orphan", 42),
        ];
        let moved_snapshot = vec![grouped_info(18_422, Some(500), "node", 77)];
        let mut ops = RecordingTreeOps::new(vec![confirmation_snapshot, moved_snapshot]);

        let reason = run_group_kill_with(
            &kill_pid_group(18_422, false),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_kill_ports: || Ok(Vec::new()),
                collect_ports: || Ok(Vec::new()),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_losing_readable_owner_during_revalidation_exits_permission_denied() {
        let rows = vec![entry(3000)];
        let preview = vec![grouped_info(18_422, Some(500), "node", 42)];
        let mut ops = RecordingTreeOps::new(vec![preview]);
        let events = Rc::clone(&ops.events);
        let fresh_rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];

        let reason = run_group_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: false,
                group: true,
            },
            &Config::default(),
            &entry_views(&rows),
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_kill_ports: || {
                    events.borrow_mut().push(RecordingTreeEvent::CollectPorts);
                    Ok(fresh_rows.clone())
                },
                collect_ports: || Ok(Vec::new()),
            },
        );

        assert_eq!(reason, ExitReason::PermissionDenied);
        assert_eq!(
            &*events.borrow(),
            &[
                RecordingTreeEvent::Pin(18_422),
                RecordingTreeEvent::CollectPorts,
            ],
        );
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_authority_refusal_has_zero_stop_or_delivery() {
        let snapshot = locally_incomplete_kill_snapshot();
        let rows = vec![entry(3000)];
        let preview = vec![grouped_info(18_422, Some(500), "node", 42)];
        let mut ops = RecordingTreeOps::new(vec![preview]);

        let reason = run_group_kill_with(
            &kill_pid_group(18_422, false),
            &Config::default(),
            &entry_views(&rows),
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_kill_ports: || {
                    crate::collector::kill_ports_from_snapshot(&snapshot, Some(18_422), None)
                },
                collect_ports: || panic!("refusal must not visibility-poll ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty());
        assert!(
            !ops.events
                .borrow()
                .iter()
                .any(|event| matches!(event, RecordingTreeEvent::Deliver(_)))
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fresh_group_growing_past_yes_skip_cap_refuses_before_any_stop() {
        let clean = vec![grouped_info(18_422, Some(500), "node", 42)];
        let mut grown = clean.clone();
        for pid in 0..u32::try_from(GROUP_YES_SKIP_MAX_PROCESSES).expect("cap fits u32") {
            grown.push(grouped_info(30_000 + pid, Some(500), "worker", 42));
        }
        let mut ops = RecordingTreeOps::new(vec![clean, grown]);

        let reason = run_group_kill_with(
            &kill_pid_group(18_422, true),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_kill_ports: || panic!("portless group root must not re-collect ports"),
                collect_ports: || panic!("portless group root must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn port_selected_group_success_separates_authority_from_visibility_polling() {
        // A port-selected root plus an already-reparented member: one word
        // prompt, then authority is re-collected before delivery and visibility
        // is polled only after successful delivery.
        let rows = vec![entry(3000)];
        let root = TreeProcessInfo {
            start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            ..grouped_info(18_422, Some(500), "node", 42)
        };
        let snapshot = vec![root, grouped_info(17_000, Some(1), "orphan", 42)];
        let mut ops = RecordingTreeOps::new(vec![snapshot]);
        let mut prompts = 0;
        let mut authority_collections = 0;
        let mut visibility_polls = 0;

        let reason = run_group_kill_with(
            &kill_port_group(3000),
            &Config::default(),
            &entry_views(&rows),
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: |_target: &KillTarget, members: &ProcessTreeTarget, _requirement| {
                    prompts += 1;
                    assert_eq!(members.len(), 2, "the prompt must name the full count");
                    Ok(true)
                },
                collect_kill_ports: || {
                    authority_collections += 1;
                    Ok(rows.clone())
                },
                collect_ports: || {
                    visibility_polls += 1;
                    Ok(Vec::new())
                },
            },
        );

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(prompts, 1, "an unprotected group asks for the word once");
        assert_eq!(authority_collections, 1);
        assert_eq!(visibility_polls, 1);
        assert_eq!(
            ops.stops,
            vec![18_422, 17_000],
            "the confirmed root freezes before the members",
        );
    }
}
