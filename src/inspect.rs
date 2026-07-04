//! The read-only family view behind `kickoutchi inspect`.
//!
//! Tree kill points downward from one confirmed root. This view exists for the
//! case where downward is not enough: a supervisor, agent, or runner keeps
//! respawning the port owner, and the *right* root to kill is somewhere above
//! it. Instead of guessing (or ever killing upward automatically), inspect
//! shows the whole neighborhood — ancestors, descendants, siblings, and, on
//! POSIX platforms, the process group — so the user can pick the real root and
//! point tree kill at it deliberately.
//!
//! Strictly read-only by design: this module renders a report string and
//! nothing else. No signals, no handles, no confirmation flow. The only kill
//! it ever mentions is the `kick kill --pid <root> --tree` hint at the end.

use std::collections::HashMap;
// Writing into a String is infallible, so the `let _ =` on each `write!` is
// discarding a Result that cannot be Err.
use std::fmt::Write as _;

use crate::display::sanitize;
use crate::model::{Platform, PortEntry};
use crate::protection::is_protected_process_name;
use crate::tree::{
    MAX_TREE_PROCESSES, ProcessTreeNode, TreePlanError, TreeProcessInfo, plan_process_tree,
};

/// Display caps. The walk itself is bounded elsewhere (the tree builder caps at
/// [`MAX_TREE_PROCESSES`], the ancestor walk at [`ANCESTOR_WALK_MAX`]); these
/// only bound how much of the bounded data lands on the terminal, with an
/// honest "and N more" for the rest.
const ANCESTORS_DISPLAY_MAX: usize = 12;
const SIBLINGS_DISPLAY_MAX: usize = 8;
const TREE_DISPLAY_MAX: usize = 20;
const GROUP_DISPLAY_MAX: usize = 16;
/// Command lines can be arbitrarily long; a report line should not be.
const COMMAND_DISPLAY_MAX_CHARS: usize = 120;
/// Ancestor chains are short in practice; the cap only guards against a cyclic
/// or corrupt parent map.
const ANCESTOR_WALK_MAX: usize = 64;

/// Why a report could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InspectError {
    /// The requested PID is not in the process table.
    TargetMissing,
}

/// Render the family report for `target_pid` from one process-table snapshot
/// plus the current socket table.
///
/// Pure aside from the injected `command_line` reader, so tests drive it with
/// a scripted table and pin the exact report shape. Every OS-provided string
/// is sanitized before it reaches the output.
pub(crate) fn render_family_report<CommandLine>(
    target_pid: u32,
    snapshot: &[TreeProcessInfo],
    entries: &[PortEntry],
    protected_names: &[String],
    platform: Platform,
    mut command_line: CommandLine,
) -> Result<String, InspectError>
where
    CommandLine: FnMut(u32) -> Option<String>,
{
    let target = snapshot
        .iter()
        .find(|info| info.pid == target_pid)
        .ok_or(InspectError::TargetMissing)?;

    let ports_by_pid = ports_by_pid(entries);
    let mut out = String::new();

    render_target(
        &mut out,
        target,
        &ports_by_pid,
        protected_names,
        platform,
        &mut command_line,
    );
    render_ancestors(
        &mut out,
        target,
        snapshot,
        protected_names,
        platform,
        &mut command_line,
    );
    render_siblings(&mut out, target, snapshot, protected_names, platform);
    let tree_pids = render_tree(
        &mut out,
        target_pid,
        snapshot,
        &ports_by_pid,
        protected_names,
        platform,
    );
    let members_outside_tree = render_group(
        &mut out,
        target,
        snapshot,
        &tree_pids,
        protected_names,
        platform,
    );

    let _ = write!(
        out,
        "\nTo terminate this tree: kick kill --pid {target_pid} --tree\n",
    );
    // Group members outside the tree are exactly what a tree kill would leave
    // alive, so that is the one case where the group command earns a mention.
    if members_outside_tree > 0 {
        let _ = writeln!(
            out,
            "To terminate the whole group instead: kick kill --pid {target_pid} --group",
        );
    }
    if platform == Platform::Windows {
        out.push_str(
            "Windows note: parent links require creation-time sanity checks, so a dangling or recycled parent PID may be omitted.\n",
        );
        out.push_str(
            "WSL2 note: native Windows cannot see individual Linux processes inside WSL2; run the Linux build inside WSL2 for those trees.\n",
        );
    }
    out.push_str("(different root? rerun inspect on an ancestor PID first)\n");
    Ok(out)
}

fn render_target<CommandLine>(
    out: &mut String,
    target: &TreeProcessInfo,
    ports_by_pid: &HashMap<u32, Vec<String>>,
    protected_names: &[String],
    platform: Platform,
    command_line: &mut CommandLine,
) where
    CommandLine: FnMut(u32) -> Option<String>,
{
    let _ = writeln!(
        out,
        "Target: {}",
        member_label(target, protected_names, platform),
    );
    if let Some(command) = command_line(target.pid) {
        let _ = writeln!(out, "  Command: {}", clipped(&command));
    }
    match ports_by_pid.get(&target.pid) {
        Some(ports) => {
            let _ = writeln!(out, "  Ports: {}", ports.join(", "));
        }
        None => out.push_str("  Ports: none visible\n"),
    }
    if platform != Platform::Windows {
        match target.process_group {
            Some(group) => {
                let _ = writeln!(out, "  Process group: {group}");
            }
            None => out.push_str("  Process group: unknown\n"),
        }
    }
}

fn render_ancestors<CommandLine>(
    out: &mut String,
    target: &TreeProcessInfo,
    snapshot: &[TreeProcessInfo],
    protected_names: &[String],
    platform: Platform,
    command_line: &mut CommandLine,
) where
    CommandLine: FnMut(u32) -> Option<String>,
{
    let ancestors = ancestor_chain(target, snapshot);
    if ancestors.is_empty() {
        out.push_str("Ancestors: none visible\n");
        return;
    }

    out.push_str("Ancestors (nearest first):\n");
    for ancestor in ancestors.iter().take(ANCESTORS_DISPLAY_MAX) {
        let _ = write!(
            out,
            "  {}",
            member_label(ancestor, protected_names, platform),
        );
        if let Some(command) = command_line(ancestor.pid) {
            let _ = write!(out, " — {}", clipped(&command));
        }
        out.push('\n');
    }
    if ancestors.len() > ANCESTORS_DISPLAY_MAX {
        let _ = writeln!(
            out,
            "  ... and {} more",
            ancestors.len() - ANCESTORS_DISPLAY_MAX,
        );
    }
}

fn render_siblings(
    out: &mut String,
    target: &TreeProcessInfo,
    snapshot: &[TreeProcessInfo],
    protected_names: &[String],
    platform: Platform,
) {
    let Some(parent_pid) = target.parent_pid else {
        return;
    };
    let mut siblings: Vec<&TreeProcessInfo> = snapshot
        .iter()
        .filter(|info| info.parent_pid == Some(parent_pid) && info.pid != target.pid)
        .collect();
    if siblings.is_empty() {
        return;
    }
    siblings.sort_by_key(|info| info.pid);

    let shown = siblings
        .iter()
        .take(SIBLINGS_DISPLAY_MAX)
        .map(|info| member_label(info, protected_names, platform))
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = if siblings.len() > SIBLINGS_DISPLAY_MAX {
        format!(" ... and {} more", siblings.len() - SIBLINGS_DISPLAY_MAX)
    } else {
        String::new()
    };
    let _ = writeln!(out, "Siblings (same parent): {shown}{suffix}");
}

/// Render the descendant tree and hand back its member PIDs so the group view
/// can mark who sits outside it.
fn render_tree(
    out: &mut String,
    target_pid: u32,
    snapshot: &[TreeProcessInfo],
    ports_by_pid: &HashMap<u32, Vec<String>>,
    protected_names: &[String],
    platform: Platform,
) -> Vec<u32> {
    let preview = match plan_process_tree(
        target_pid,
        snapshot,
        protected_names,
        platform,
        MAX_TREE_PROCESSES,
    ) {
        Ok(preview) => preview,
        // The target row was found by the caller, so only a racing exit lands
        // here; report the tree as just the target rather than failing the
        // whole report.
        Err(TreePlanError::RootMissing) => {
            let _ = writeln!(out, "Tree: only PID {target_pid} (already exiting?)");
            return vec![target_pid];
        }
    };

    let truncation_note = if preview.truncated() {
        format!(" (enumeration capped at {MAX_TREE_PROCESSES})")
    } else {
        String::new()
    };
    let _ = writeln!(out, "Tree ({} processes){truncation_note}:", preview.len());
    for node in preview.preview_nodes(TREE_DISPLAY_MAX) {
        let indent = "  ".repeat(node.depth + 1);
        let _ = write!(out, "{indent}{}", node_label(node));
        if let Some(ports) = ports_by_pid.get(&node.pid) {
            let _ = write!(out, " [{}]", ports.join(", "));
        }
        out.push('\n');
    }
    if preview.len() > TREE_DISPLAY_MAX {
        let _ = writeln!(out, "  ... and {} more", preview.len() - TREE_DISPLAY_MAX);
    }

    preview
        .preview_nodes(preview.len())
        .iter()
        .map(|node| node.pid)
        .collect()
}

/// Render the process-group section and return how many members sit outside
/// the descendant tree, so the footer can decide whether the group-kill hint
/// is worth printing.
fn render_group(
    out: &mut String,
    target: &TreeProcessInfo,
    snapshot: &[TreeProcessInfo],
    tree_pids: &[u32],
    protected_names: &[String],
    platform: Platform,
) -> usize {
    if platform == Platform::Windows {
        return 0;
    }
    let Some(group) = target.process_group else {
        return 0;
    };
    let mut members: Vec<&TreeProcessInfo> = snapshot
        .iter()
        .filter(|info| info.process_group == Some(group))
        .collect();
    members.sort_by_key(|info| info.pid);

    // Members outside the descendant tree are the interesting ones: they are
    // exactly what a tree kill from this target would leave alive.
    let outside_count = members
        .iter()
        .filter(|info| !tree_pids.contains(&info.pid))
        .count();
    let _ = writeln!(
        out,
        "Process group {group} ({} members, {outside_count} outside the tree):",
        members.len(),
    );
    for member in members.iter().take(GROUP_DISPLAY_MAX) {
        let marker = if tree_pids.contains(&member.pid) {
            ""
        } else {
            " — outside the tree"
        };
        let _ = writeln!(
            out,
            "  {}{marker}",
            member_label(member, protected_names, platform),
        );
    }
    if members.len() > GROUP_DISPLAY_MAX {
        let _ = writeln!(out, "  ... and {} more", members.len() - GROUP_DISPLAY_MAX);
    }
    outside_count
}

/// Walk the parent map upward: nearest ancestor first. Bounded, and the seen
/// set makes a cyclic or corrupt parent map terminate instead of looping.
fn ancestor_chain<'snapshot>(
    target: &TreeProcessInfo,
    snapshot: &'snapshot [TreeProcessInfo],
) -> Vec<&'snapshot TreeProcessInfo> {
    let mut chain = Vec::new();
    let mut seen = vec![target.pid];
    let mut parent_pid = target.parent_pid;

    for _ in 0..ANCESTOR_WALK_MAX {
        let Some(pid) = parent_pid else {
            break;
        };
        if seen.contains(&pid) {
            break;
        }
        let Some(info) = snapshot.iter().find(|info| info.pid == pid) else {
            break;
        };
        seen.push(pid);
        chain.push(info);
        parent_pid = info.parent_pid;
    }
    chain
}

fn ports_by_pid(entries: &[PortEntry]) -> HashMap<u32, Vec<String>> {
    let mut ports: HashMap<u32, Vec<String>> = HashMap::new();
    for entry in entries {
        let Some(pid) = entry.pid else {
            continue;
        };
        ports.entry(pid).or_default().push(format!(
            "{} {}:{}",
            entry.protocol.label(),
            entry.local_addr,
            entry.local_port,
        ));
    }
    ports
}

fn member_label(info: &TreeProcessInfo, protected_names: &[String], platform: Platform) -> String {
    let name = sanitize(info.process_name.as_deref().unwrap_or("<unknown>"));
    let protected = info
        .process_name
        .as_deref()
        .is_some_and(|name| is_protected_process_name(platform, name, protected_names));
    let marker = if protected { " [protected]" } else { "" };
    format!("PID {} ({name}){marker}", info.pid)
}

fn node_label(node: &ProcessTreeNode) -> String {
    let name = sanitize(node.process_name.as_deref().unwrap_or("<unknown>"));
    let marker = if node.protected { " [protected]" } else { "" };
    format!("PID {} ({name}){marker}", node.pid)
}

fn clipped(command: &str) -> String {
    let sanitized = sanitize(command);
    if sanitized.chars().count() <= COMMAND_DISPLAY_MAX_CHARS {
        return sanitized;
    }
    let mut clipped: String = sanitized.chars().take(COMMAND_DISPLAY_MAX_CHARS).collect();
    clipped.push_str("...");
    clipped
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{InspectError, render_family_report};
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState};
    use crate::tree::TreeProcessInfo;

    fn info(pid: u32, parent: Option<u32>, name: &str, group: u32) -> TreeProcessInfo {
        TreeProcessInfo {
            pid,
            parent_pid: parent,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some(name.to_owned()),
            start_time_marker: Some(u64::from(pid)),
            owner_uid: None,
            process_group: Some(group),
        }
    }

    fn port_entry(pid: u32, port: u16) -> PortEntry {
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
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
        }
    }

    /// The supervisor scenario the view exists for: agent -> shell -> runner ->
    /// server (owns the port), with a group member outside the tree.
    fn family_snapshot() -> Vec<TreeProcessInfo> {
        vec![
            info(1, None, "systemd", 1),
            info(100, Some(1), "agent", 100),
            info(200, Some(100), "zsh", 100),
            info(300, Some(200), "npm", 300),
            info(400, Some(300), "node", 300), // target: owns the port
            info(401, Some(400), "worker", 300), // descendant
            info(310, Some(200), "vite", 300), // sibling of npm under zsh
            info(999, Some(1), "watchman", 300), // same group, outside the tree
        ]
    }

    fn render(target: u32) -> String {
        render_family_report(
            target,
            &family_snapshot(),
            &[port_entry(400, 3000)],
            &["postgres".to_owned()],
            Platform::Linux,
            |pid| (pid == 300).then(|| "npm run dev".to_owned()),
        )
        .expect("target is present")
    }

    #[test]
    fn report_walks_ancestors_nearest_first() {
        let report = render(400);

        let npm = report
            .find("PID 300 (npm)")
            .expect("nearest ancestor shown");
        let zsh = report.find("PID 200 (zsh)").expect("shell shown");
        let agent = report.find("PID 100 (agent)").expect("agent shown");
        let init = report.find("PID 1 (systemd)").expect("chain reaches init");
        assert!(npm < zsh && zsh < agent && agent < init, "{report}");
        // The ancestor command line helps identify the supervisor.
        assert!(report.contains("npm run dev"), "{report}");
    }

    #[test]
    fn report_shows_target_ports_tree_and_kill_hint() {
        let report = render(400);

        assert!(report.contains("Target: PID 400 (node)"), "{report}");
        assert!(report.contains("Ports: TCP 127.0.0.1:3000"), "{report}");
        assert!(report.contains("Tree (2 processes)"), "{report}");
        assert!(report.contains("PID 401 (worker)"), "{report}");
        assert!(report.contains("kick kill --pid 400 --tree"), "{report}");
    }

    #[test]
    fn report_marks_group_members_outside_the_tree() {
        let report = render(400);

        assert!(
            report.contains("Process group 300 (5 members, 3 outside the tree)"),
            "{report}",
        );
        assert!(
            report.contains("PID 999 (watchman) — outside the tree"),
            "{report}",
        );
        // Members inside the tree carry no marker.
        assert!(!report.contains("PID 401 (worker) — outside"), "{report}");
        // Members outside the tree are exactly what a tree kill would leave
        // alive, so the footer must offer the group command too.
        assert!(report.contains("kick kill --pid 400 --group"), "{report}");
    }

    #[test]
    fn group_kill_hint_is_absent_when_the_tree_already_covers_the_group() {
        // The agent's group (100) contains only itself and its shell child —
        // both inside its descendant tree — so suggesting a group kill would
        // add scope without adding coverage.
        let report = render(100);

        assert!(report.contains("0 outside the tree"), "{report}");
        assert!(report.contains("kick kill --pid 100 --tree"), "{report}");
        assert!(!report.contains("--group"), "{report}");
    }

    #[test]
    fn windows_report_omits_posix_group_sections_and_notes_wsl2_limit() {
        let report = render_family_report(
            400,
            &family_snapshot(),
            &[port_entry(400, 3000)],
            &[],
            Platform::Windows,
            |_| None,
        )
        .expect("target is present");

        assert!(!report.contains("Process group"), "{report}");
        assert!(!report.contains("--group"), "{report}");
        assert!(report.contains("Windows note"), "{report}");
        assert!(report.contains("WSL2 note"), "{report}");
        assert!(report.contains("kick kill --pid 400 --tree"), "{report}");
    }

    #[test]
    fn report_lists_siblings_without_the_target() {
        // Inspect the runner: its sibling under the shell is vite.
        let report = render(300);

        assert!(
            report.contains("Siblings (same parent): PID 310 (vite)"),
            "{report}",
        );
        assert!(
            !report.contains("Siblings (same parent): PID 300"),
            "{report}",
        );
    }

    #[test]
    fn missing_target_is_the_only_report_error() {
        let error =
            render_family_report(4242, &family_snapshot(), &[], &[], Platform::Linux, |_| {
                None
            })
            .expect_err("absent PID cannot be inspected");

        assert_eq!(error, InspectError::TargetMissing);
    }

    #[test]
    fn protected_members_are_marked_and_names_sanitized() {
        let mut snapshot = family_snapshot();
        snapshot.push(info(500, Some(400), "postgres", 300));
        snapshot.push(TreeProcessInfo {
            pid: 501,
            parent_pid: Some(400),
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("evil\x1b[2Jname".to_owned()),
            start_time_marker: Some(501),
            owner_uid: None,
            process_group: Some(300),
        });

        let report = render_family_report(
            400,
            &snapshot,
            &[],
            &["postgres".to_owned()],
            Platform::Linux,
            |_| None,
        )
        .expect("target is present");

        assert!(
            report.contains("PID 500 (postgres) [protected]"),
            "{report}",
        );
        // The ANSI escape must not survive into the terminal.
        assert!(!report.contains('\x1b'), "{report}");
        assert!(report.contains("evilname"), "{report}");
    }

    #[test]
    fn cyclic_parent_maps_terminate_the_ancestor_walk() {
        // A corrupt map: 100 and 200 claim each other as parents.
        let snapshot = vec![
            info(100, Some(200), "a", 100),
            info(200, Some(100), "b", 100),
        ];

        let report = render_family_report(100, &snapshot, &[], &[], Platform::Linux, |_| None)
            .expect("target present");

        // The walk shows the one real ancestor and stops instead of looping.
        assert!(report.contains("PID 200 (b)"), "{report}");
    }
}
