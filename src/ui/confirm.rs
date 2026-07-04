//! The "wait, are you sure you want to kill this?" modal.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::app::{self, App, KillConfirmation};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::app::{TreeConfirmStage, TreeKillConfirmation};
use crate::display::sanitize;
use crate::process::ConfirmationRequirement;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process::tree_scope_warning_text;

use super::{field, theme::Theme};

/// Ceiling on the node preview inside the tree confirmation modal. The actual
/// number of preview rows is budgeted per render from the modal height, so the
/// typed-word instruction, the input echo, and the Esc hint can never fall
/// below the fold — a confirmation must not accept input it is not showing.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const TREE_MODAL_PREVIEW_MAX: usize = 8;

/// Floor on the node preview: the root row always shows, however small the
/// modal gets.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const TREE_MODAL_PREVIEW_MIN: usize = 1;

pub(crate) fn render(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let lines = app.kill_confirmation().map_or_else(
        || {
            vec![Line::styled(
                "No termination target selected.",
                theme.muted(),
            )]
        },
        |confirmation| confirmation_lines(confirmation, theme),
    );

    let modal = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title("Confirm Termination")
            .title_style(theme.title())
            .border_style(theme.border()),
    );
    frame.render_widget(Clear, area);
    frame.render_widget(modal, area);
}

/// Render the tree-kill confirmation modal.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn render_tree(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    // Rows available inside the borders drive the preview budget, so the
    // prompt block stays visible at every supported terminal size.
    let content_rows = usize::from(area.height.saturating_sub(2));
    let lines = app.tree_confirmation().map_or_else(
        || {
            vec![Line::styled(
                "No tree termination target selected.",
                theme.muted(),
            )]
        },
        |confirmation| tree_confirmation_lines(confirmation, theme, content_rows),
    );

    let modal = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title("Confirm Tree Termination")
            .title_style(theme.title())
            .border_style(theme.border()),
    );
    frame.render_widget(Clear, area);
    frame.render_widget(modal, area);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_confirmation_lines(
    confirmation: &TreeKillConfirmation,
    theme: Theme,
    content_rows: usize,
) -> Vec<Line<'static>> {
    let preview_budget = tree_preview_budget(confirmation, content_rows);
    let mut lines = vec![
        Line::styled(
            format!(
                "{} process tree from {}",
                confirmation
                    .mode
                    .action_label_for(confirmation.target.platform),
                confirmation.target.identity(),
            ),
            theme.title(),
        ),
        field("Ports", sanitize(&confirmation.target.ports_text()), theme),
    ];

    let preview_ready = confirmation.preview.is_some();
    match &confirmation.preview {
        // The background worker is still walking the process table; the modal
        // must say so instead of showing a count it does not have or accepting
        // a word before the user can review that count.
        None => lines.push(Line::styled(
            "Enumerating the process tree...",
            theme.muted(),
        )),
        Some(preview) => {
            lines.push(field(
                "Scope",
                format!("tree ({} processes)", preview.len()),
                theme,
            ));
            for node in preview.preview_nodes(preview_budget) {
                let indent = "  ".repeat(node.depth + 1);
                let name = sanitize(node.process_name.as_deref().unwrap_or("<unknown>"));
                lines.push(Line::raw(format!("{indent}PID {} ({name})", node.pid)));
            }
            if preview.len() > preview_budget {
                lines.push(Line::raw(format!(
                    "  ... and {} more",
                    preview.len() - preview_budget,
                )));
            }
            if preview.has_system_process() {
                lines.push(Line::styled(
                    "Warning: tree includes system/service processes; verify this is safe to terminate.",
                    theme.warning(),
                ));
            }
            if preview.has_owner_mismatch() {
                lines.push(Line::styled(
                    "Warning: tree includes processes owned by another uid; verify this is safe to terminate.",
                    theme.warning(),
                ));
            }
        }
    }

    if let Some(warning) = confirmation
        .mode
        .force_warning(confirmation.target.platform)
    {
        lines.push(Line::styled(format!("Warning: {warning}"), theme.warning()));
    }
    for warning in confirmation.target.warning_lines() {
        lines.push(Line::styled(
            format!("Warning: {}.", sanitize(&tree_scope_warning_text(&warning))),
            theme.warning(),
        ));
    }

    lines.push(Line::raw(""));
    lines.push(tree_instruction_line(confirmation, theme));
    if preview_ready {
        lines.push(field("Input", confirmation.input.clone(), theme));
    }
    if let Some(error) = &confirmation.error {
        lines.push(Line::styled(format!("Error: {error}"), theme.warning()));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("Esc", theme.key()),
        Span::raw(" cancels."),
    ]));

    lines
}

/// How many preview node rows fit once every other line of the modal is
/// accounted for. Counts the same lines `tree_confirmation_lines` emits —
/// header, ports, scope, the "... and N more" reserve, warnings, and the
/// blank/instruction/input/error/Esc block — and gives the preview whatever
/// remains, clamped to `[TREE_MODAL_PREVIEW_MIN, TREE_MODAL_PREVIEW_MAX]`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_preview_budget(confirmation: &TreeKillConfirmation, content_rows: usize) -> usize {
    let preview_overhead = match &confirmation.preview {
        // Loading state renders one placeholder line and no nodes.
        None => 1,
        Some(preview) => {
            // Scope line, a reserved "... and N more" row, and the
            // scoped preview warnings when they apply.
            2 + usize::from(preview.has_system_process())
                + usize::from(preview.has_owner_mismatch())
        }
    };
    let force_warning_rows = usize::from(
        confirmation
            .mode
            .force_warning(confirmation.target.platform)
            .is_some(),
    );
    let target_warning_rows = confirmation.target.warning_lines().len();
    let error_rows = usize::from(confirmation.error.is_some());
    let input_rows = usize::from(confirmation.preview.is_some());
    // Header + ports, then blank + instruction + optional input + blank + Esc.
    let fixed_rows = 2
        + preview_overhead
        + force_warning_rows
        + target_warning_rows
        + 4
        + input_rows
        + error_rows;
    content_rows
        .saturating_sub(fixed_rows)
        .clamp(TREE_MODAL_PREVIEW_MIN, TREE_MODAL_PREVIEW_MAX)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_instruction_line(confirmation: &TreeKillConfirmation, theme: Theme) -> Line<'static> {
    if confirmation.preview.is_none() {
        return Line::from(vec![Span::raw(
            "Wait for the process count before typing confirmation.",
        )]);
    }
    match confirmation.stage {
        TreeConfirmStage::ProtectedRoot => Line::from(vec![
            Span::raw("Protected root: type "),
            Span::styled(confirmation.target.pid.to_string(), theme.key()),
            Span::raw(" or "),
            Span::styled(
                sanitize(confirmation.target.process_name_or_unknown()),
                theme.key(),
            ),
            Span::raw(", press "),
            Span::styled("Enter", theme.key()),
            Span::raw(", then confirm the tree word."),
        ]),
        TreeConfirmStage::Word => Line::from(vec![
            Span::raw("Type "),
            Span::styled(confirmation.scope_word(), theme.key()),
            Span::raw(" and press "),
            Span::styled("Enter", theme.key()),
            Span::raw(format!(
                " to send {} to all processes above.",
                confirmation
                    .mode
                    .delivery_label(confirmation.target.platform),
            )),
        ]),
    }
}

fn confirmation_lines(confirmation: &KillConfirmation, theme: Theme) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled(
            format!(
                "{} {}",
                confirmation
                    .mode
                    .action_label_for(confirmation.target.platform),
                confirmation.target.identity(),
            ),
            theme.title(),
        ),
        field("Ports", sanitize(&confirmation.target.ports_text()), theme),
        field(
            "Command",
            sanitize(&app::kill_command_text(
                &confirmation.target,
                confirmation.mode,
            )),
            theme,
        ),
    ];

    if let Some(warning) = confirmation
        .mode
        .force_warning(confirmation.target.platform)
    {
        lines.push(Line::styled(format!("Warning: {warning}"), theme.warning()));
    }
    for warning in confirmation.target.warning_lines() {
        lines.push(Line::styled(
            format!("Warning: {}.", sanitize(&warning)),
            theme.warning(),
        ));
    }

    lines.push(Line::raw(""));
    lines.push(instruction_line(confirmation, theme));
    if confirmation.requirement != ConfirmationRequirement::Yes {
        lines.push(field("Input", confirmation.input.clone(), theme));
    }
    if let Some(error) = &confirmation.error {
        lines.push(Line::styled(format!("Error: {error}"), theme.warning()));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("Esc", theme.key()),
        Span::raw(" cancels."),
    ]));

    lines
}

fn instruction_line(confirmation: &KillConfirmation, theme: Theme) -> Line<'static> {
    match confirmation.requirement {
        ConfirmationRequirement::Yes => Line::from(vec![
            Span::styled("y", theme.key()),
            Span::raw(format!(
                " confirms {}. ",
                confirmation
                    .mode
                    .action_label_for(confirmation.target.platform)
                    .to_ascii_lowercase(),
            )),
            Span::styled("n", theme.key()),
            Span::raw(" cancels."),
        ]),
        ConfirmationRequirement::ForceWord => Line::from(vec![
            Span::raw("Type "),
            Span::styled("force", theme.key()),
            Span::raw(" and press "),
            Span::styled("Enter", theme.key()),
            Span::raw(format!(
                " to send {}.",
                confirmation
                    .mode
                    .delivery_label(confirmation.target.platform),
            )),
        ]),
        ConfirmationRequirement::ProtectedProcess => Line::from(vec![
            Span::raw("Protected process: type "),
            Span::styled(confirmation.target.pid.to_string(), theme.key()),
            Span::raw(" or "),
            Span::styled(
                sanitize(confirmation.target.process_name_or_unknown()),
                theme.key(),
            ),
            Span::raw(" and press "),
            Span::styled("Enter", theme.key()),
            Span::raw("."),
        ]),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::confirmation_lines;
    use crate::app::KillConfirmation;
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState};
    use crate::process::{ConfirmationRequirement, KillMode, KillTarget};
    use crate::ui::theme::Theme;

    fn target(protected: bool) -> KillTarget {
        let row = PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: Some(18422),
            process_name: Some("node".to_owned()),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            child_pids: Vec::new(),
            protected,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
        };
        KillTarget::from_entries(18422, [&row], None)
    }

    #[test]
    fn confirmation_lines_show_command_and_required_input() {
        let confirmation = KillConfirmation {
            target: target(false),
            mode: KillMode::Force,
            requirement: ConfirmationRequirement::ForceWord,
            input: "for".to_owned(),
            error: Some("keep typing".to_owned()),
        };
        let text = confirmation_lines(&confirmation, Theme::from_environment())
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("kill -9 18422"), "{text}");
        assert!(text.contains("force"), "{text}");
        assert!(text.contains("Input: for"), "{text}");
        assert!(text.contains("keep typing"), "{text}");
    }

    #[test]
    fn protected_confirmation_requires_pid_or_name() {
        let confirmation = KillConfirmation {
            target: target(true),
            mode: KillMode::Terminate,
            requirement: ConfirmationRequirement::ProtectedProcess,
            input: String::new(),
            error: None,
        };
        let text = confirmation_lines(&confirmation, Theme::from_environment())
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Protected process"), "{text}");
        assert!(text.contains("18422"), "{text}");
        assert!(text.contains("node"), "{text}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_lines_cover_loading_word_and_protected_stages() {
        use super::tree_confirmation_lines;
        use crate::app::{TreeConfirmStage, TreeKillConfirmation};

        // A tall modal: the preview budget is not the constraint here.
        let render = |confirmation: &TreeKillConfirmation| {
            tree_confirmation_lines(confirmation, Theme::from_environment(), 40)
                .into_iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };

        // Loading: no count yet, and the modal must say so.
        let mut confirmation = TreeKillConfirmation {
            target: target(false),
            mode: KillMode::Terminate,
            preview: None,
            stage: TreeConfirmStage::Word,
            input: String::new(),
            error: None,
        };
        let text = render(&confirmation);
        assert!(text.contains("Enumerating the process tree"), "{text}");
        assert!(text.contains("Wait for the process count"), "{text}");
        assert!(!text.contains("Type tree"), "{text}");
        assert!(!text.contains("Input:"), "{text}");

        // Loaded word stage: count, node list, and the exact word to type.
        let infos = vec![
            crate::tree::TreeProcessInfo {
                pid: 18422,
                parent_pid: Some(1),
                parent_process_name: None,
                process_name: Some("node".to_owned()),
                start_time_marker: Some(55),
                owner_uid: None,
                process_group: None,
            },
            crate::tree::TreeProcessInfo {
                pid: 18430,
                parent_pid: Some(18422),
                parent_process_name: None,
                process_name: Some("worker".to_owned()),
                start_time_marker: Some(56),
                owner_uid: None,
                process_group: None,
            },
        ];
        confirmation.preview = Some(
            crate::tree::plan_process_tree(18422, &infos, &[], crate::model::Platform::Linux, 256)
                .expect("preview must build"),
        );
        let text = render(&confirmation);
        assert!(text.contains("tree (2 processes)"), "{text}");
        assert!(text.contains("PID 18430 (worker)"), "{text}");
        assert!(text.contains("Type tree"), "{text}");
        assert!(text.contains("SIGTERM"), "{text}");

        // Protected stage names both facts the user must type, in order.
        confirmation.target = target(true);
        confirmation.stage = TreeConfirmStage::ProtectedRoot;
        let text = render(&confirmation);
        assert!(text.contains("Protected root"), "{text}");
        assert!(text.contains("18422"), "{text}");
        assert!(text.contains("then confirm the tree word"), "{text}");
    }

    /// At the smallest supported modal (80x20 terminal -> 13 content rows),
    /// a large tree must shrink its preview rather than push the typed-word
    /// instruction, the input echo, or the Esc hint below the fold: the modal
    /// keeps accepting keystrokes, so what it asks for must stay visible.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_prompt_stays_visible_at_minimum_modal_height() {
        use super::tree_confirmation_lines;
        use crate::app::{TreeConfirmStage, TreeKillConfirmation};

        let mut infos = vec![crate::tree::TreeProcessInfo {
            pid: 18422,
            parent_pid: Some(500),
            parent_process_name: None,
            process_name: Some("node".to_owned()),
            start_time_marker: Some(55),
            owner_uid: None,
            process_group: None,
        }];
        for pid in 18430..18450 {
            infos.push(crate::tree::TreeProcessInfo {
                pid,
                parent_pid: Some(18422),
                parent_process_name: None,
                process_name: Some("worker".to_owned()),
                start_time_marker: Some(u64::from(pid)),
                owner_uid: None,
                process_group: None,
            });
        }
        let confirmation = TreeKillConfirmation {
            target: target(false),
            mode: KillMode::Force,
            preview: Some(
                crate::tree::plan_process_tree(
                    18422,
                    &infos,
                    &[],
                    crate::model::Platform::Linux,
                    256,
                )
                .expect("preview must build"),
            ),
            stage: TreeConfirmStage::Word,
            input: "for".to_owned(),
            error: Some("keep typing".to_owned()),
        };

        // 80x20 terminal, 76% modal height = 15 rows, minus borders = 13.
        let content_rows = 13;
        let lines = tree_confirmation_lines(&confirmation, Theme::from_environment(), content_rows);
        assert!(
            lines.len() <= content_rows,
            "modal emits {} lines for {content_rows} rows",
            lines.len(),
        );
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Type force"), "{text}");
        assert!(text.contains("Input: for"), "{text}");
        assert!(text.contains("keep typing"), "{text}");
        assert!(text.contains("Esc cancels."), "{text}");
        // The tree size stays honest even when the node list is clipped.
        assert!(text.contains("tree (21 processes)"), "{text}");
        assert!(text.contains("more"), "{text}");
    }

    #[test]
    fn yes_confirmation_names_force_kill_when_force_is_selected() {
        let confirmation = KillConfirmation {
            target: target(false),
            mode: KillMode::Force,
            requirement: ConfirmationRequirement::Yes,
            input: String::new(),
            error: None,
        };
        let text = confirmation_lines(&confirmation, Theme::from_environment())
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("confirms force-kill"), "{text}");
        assert!(!text.contains("confirms normal termination"), "{text}");
    }
}
