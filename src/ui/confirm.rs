//! The "wait, are you sure you want to kill this?" modal.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ratatui::widgets::Wrap;
use ratatui::widgets::{Block, Clear, Paragraph};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use unicode_width::UnicodeWidthStr;

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
    let content_rows = usize::from(area.height.saturating_sub(2));
    let lines = app.kill_confirmation().map_or_else(
        || {
            vec![Line::styled(
                "No termination target selected.",
                theme.muted(),
            )]
        },
        |confirmation| confirmation_lines(confirmation, theme, content_rows),
    );

    let scroll = u16::try_from(lines.len().saturating_sub(content_rows)).unwrap_or(u16::MAX);
    let modal = Paragraph::new(lines).scroll((scroll, 0)).block(
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
    let content_cols = usize::from(area.width.saturating_sub(2));
    let lines = app.tree_confirmation().map_or_else(
        || {
            vec![Line::styled(
                "No tree termination target selected.",
                theme.muted(),
            )]
        },
        |confirmation| tree_confirmation_lines(confirmation, theme, content_rows, content_cols),
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
    content_cols: usize,
) -> Vec<Line<'static>> {
    let preview_budget = tree_preview_budget(confirmation, content_rows, content_cols);
    let mut lines = vec![
        Line::styled(tree_header_text(confirmation), theme.title()),
        field(
            "Ports",
            clipped_field_value(
                &sanitize(&confirmation.target.ports_text()),
                "Ports",
                content_cols,
            ),
            theme,
        ),
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
fn tree_preview_budget(
    confirmation: &TreeKillConfirmation,
    content_rows: usize,
    content_cols: usize,
) -> usize {
    let preview_overhead = match &confirmation.preview {
        // Loading state renders one placeholder line and no nodes.
        None => wrapped_rows("Enumerating the process tree...", content_cols),
        Some(preview) => {
            // Scope line, a reserved "... and N more" row, and the
            // scoped preview warnings when they apply.
            wrapped_rows(
                &format!("Scope: tree ({} processes)", preview.len()),
                content_cols,
            ) + 1
                + if preview.has_system_process() {
                    wrapped_rows(
                        "Warning: tree includes system/service processes; verify this is safe to terminate.",
                        content_cols,
                    )
                } else {
                    0
                }
                + if preview.has_owner_mismatch() {
                    wrapped_rows(
                        "Warning: tree includes processes owned by another uid; verify this is safe to terminate.",
                        content_cols,
                    )
                } else {
                    0
                }
        }
    };
    let force_warning_rows = confirmation
        .mode
        .force_warning(confirmation.target.platform)
        .map_or(0, |warning| {
            wrapped_rows(&format!("Warning: {warning}"), content_cols)
        });
    let target_warning_rows = confirmation
        .target
        .warning_lines()
        .into_iter()
        .map(|warning| {
            wrapped_rows(
                &format!("Warning: {}.", sanitize(&tree_scope_warning_text(&warning))),
                content_cols,
            )
        })
        .sum::<usize>();
    let error_rows = confirmation.error.as_ref().map_or(0, |error| {
        wrapped_rows(&format!("Error: {error}"), content_cols)
    });
    let input_rows = if confirmation.preview.is_some() {
        wrapped_rows(&format!("Input: {}", confirmation.input), content_cols)
    } else {
        0
    };
    let fixed_rows = wrapped_rows(&tree_header_text(confirmation), content_cols)
        + 1
        + preview_overhead
        + force_warning_rows
        + target_warning_rows
        + 2
        + wrapped_rows(&tree_instruction_text(confirmation), content_cols)
        + input_rows
        + error_rows
        + wrapped_rows("Esc cancels.", content_cols);
    content_rows
        .saturating_sub(fixed_rows)
        .clamp(TREE_MODAL_PREVIEW_MIN, TREE_MODAL_PREVIEW_MAX)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_header_text(confirmation: &TreeKillConfirmation) -> String {
    format!(
        "{} process tree from {}",
        confirmation
            .mode
            .action_label_for(confirmation.target.platform),
        confirmation.target.identity(),
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_instruction_text(confirmation: &TreeKillConfirmation) -> String {
    if confirmation.preview.is_none() {
        return "Wait for the process count before typing confirmation.".to_owned();
    }
    match confirmation.stage {
        TreeConfirmStage::ProtectedRoot => format!(
            "Protected root: type {} or {}, press Enter, then confirm the tree word.",
            confirmation.target.pid,
            sanitize(confirmation.target.process_name_or_unknown()),
        ),
        TreeConfirmStage::Word => format!(
            "Type {} and press Enter to send {} to all processes above.",
            confirmation.scope_word(),
            confirmation
                .mode
                .delivery_label(confirmation.target.platform),
        ),
    }
}

/// Upper-bound row count for one logical line under the modal's
/// `Wrap { trim: false }` word wrapping.
///
/// `ceil(chars / cols)` is only a lower bound: word wrapping pushes a word
/// that does not fit onto the next row, so the columns wasted at each break
/// can add rows — three 11-column words at 20 columns take three rows, not
/// two. This walks the same greedy model (words fill a row until the next
/// word no longer fits; a word wider than the modal hard-breaks), measured
/// in terminal columns so double-width names count honestly. Where this
/// model and the widget could disagree, the accounting rounds up: an
/// overcount only shrinks the node preview, an undercount would push the
/// prompt below the fold.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn wrapped_rows(text: &str, content_cols: usize) -> usize {
    let cols = content_cols.max(1);
    let mut rows: usize = 1;
    let mut used_cols: usize = 0;
    let mut first_word = true;

    for word in text.split(' ') {
        // Every split boundary is exactly one space; it travels with the
        // word it precedes, so runs of spaces keep their full width.
        let separator_cols = usize::from(!first_word);
        first_word = false;
        let word_cols = word.width();
        if used_cols + separator_cols + word_cols <= cols {
            used_cols += separator_cols + word_cols;
            continue;
        }
        if used_cols > 0 {
            rows += 1;
        }
        if word_cols <= cols {
            used_cols = word_cols;
        } else {
            // Hard break: charge full rows and treat the last one as spent,
            // which rounds up instead of tracking the exact remainder.
            rows += word_cols.div_ceil(cols) - 1;
            used_cols = cols;
        }
    }

    // The character mass is a hard floor however the breaks land.
    rows.max(text.width().div_ceil(cols)).max(1)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn clipped_field_value(value: &str, label: &str, content_cols: usize) -> String {
    let available = content_cols
        .saturating_sub(label.chars().count() + 2)
        .max(1);
    clipped_chars(value, available)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn clipped_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }
    let mut clipped = value.chars().take(max_chars - 3).collect::<String>();
    clipped.push_str("...");
    clipped
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

fn confirmation_lines(
    confirmation: &KillConfirmation,
    theme: Theme,
    content_rows: usize,
) -> Vec<Line<'static>> {
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

    if lines.len() > content_rows {
        lines.retain(|line| line.width() != 0);
    }
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
            process_name: Some("node".into()),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            child_pids: Vec::new(),
            protected,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: Some(crate::observation::ProcessIdentity {
                pid: 18422,
                start_marker: crate::observation::ProcessStartMarker::linux(55)
                    .expect("test marker is nonzero"),
            }),
            ipv6_scope: None,
        };
        KillTarget::from_entries(18422, [&row], None)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn target_with_port_count(count: u16) -> KillTarget {
        let rows = (0..count)
            .map(|offset| PortEntry {
                protocol: Protocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                local_port: 3000 + offset,
                state: SocketState::Listen,
                pid: Some(18422),
                process_name: Some("node".into()),
                executable_path: None,
                command_line: None,
                parent_pid: None,
                parent_process_name: None,
                child_pids: Vec::new(),
                protected: false,
                platform: Platform::Linux,
                permission: PermissionStatus::Full,
                process_identity: Some(crate::observation::ProcessIdentity {
                    pid: 18422,
                    start_marker: crate::observation::ProcessStartMarker::linux(55)
                        .expect("test marker is nonzero"),
                }),
                ipv6_scope: None,
            })
            .collect::<Vec<_>>();
        KillTarget::from_entries(18422, rows.iter(), None)
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
        let text = confirmation_lines(&confirmation, Theme::from_environment(), 40)
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
        let text = confirmation_lines(&confirmation, Theme::from_environment(), 40)
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
            tree_confirmation_lines(confirmation, Theme::from_environment(), 40, 100)
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
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: Some("node".to_owned()),
                start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
                owner_uid: None,
                process_group: None,
            },
            crate::tree::TreeProcessInfo {
                pid: 18430,
                parent_pid: Some(18422),
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: Some("worker".to_owned()),
                start_time_marker: crate::observation::ProcessStartMarker::linux(56).ok(),
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
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some("node".to_owned()),
            start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            owner_uid: None,
            process_group: None,
        }];
        for pid in 18430..18450 {
            infos.push(crate::tree::TreeProcessInfo {
                pid,
                parent_pid: Some(18422),
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: Some("worker".to_owned()),
                start_time_marker: crate::observation::ProcessStartMarker::linux(u64::from(pid))
                    .ok(),
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
        let lines =
            tree_confirmation_lines(&confirmation, Theme::from_environment(), content_rows, 78);
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn wrapped_rows_counts_word_wrap_waste_not_just_character_mass() {
        use super::wrapped_rows;

        // Three 11-column words at 20 columns: greedy word wrap fits one word
        // per row (11 + space + 11 overflows), so the widget spends 3 rows
        // where a plain character count claims ceil(35/20) = 2. Undercounting
        // here is what lets the preview push the prompt below the fold.
        assert_eq!(wrapped_rows("aaaaaaaaaaa bbbbbbbbbbb ccccccccccc", 20), 3);
        // Double-width names occupy two columns per char.
        assert_eq!(wrapped_rows("数据库数据库", 6), 2);
        // A single word wider than the modal hard-breaks across rows.
        assert_eq!(wrapped_rows(&"x".repeat(45), 20), 3);
        // Boundary cases keep the one-row floor.
        assert_eq!(wrapped_rows("", 20), 1);
        assert_eq!(wrapped_rows("short", 20), 1);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_clips_long_ports_line_to_modal_width() {
        use super::tree_confirmation_lines;
        use crate::app::{TreeConfirmStage, TreeKillConfirmation};

        let confirmation = TreeKillConfirmation {
            target: target_with_port_count(20),
            mode: KillMode::Terminate,
            preview: None,
            stage: TreeConfirmStage::Word,
            input: String::new(),
            error: None,
        };

        let lines = tree_confirmation_lines(&confirmation, Theme::from_environment(), 10, 32);
        let ports = lines
            .iter()
            .map(ToString::to_string)
            .find(|line| line.starts_with("Ports: "))
            .expect("ports line is rendered");
        assert!(ports.ends_with("..."), "{ports}");
        assert!(ports.chars().count() <= 32, "{ports}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn crowded_single_confirmation_keeps_actionable_lines_visible() {
        let mut crowded_target = target_with_port_count(20);
        crowded_target.process_name = Some("very-long-process-name".repeat(8));
        crowded_target.protected = true;
        crowded_target.system_process = true;
        crowded_target.permission = PermissionStatus::Partial;
        crowded_target.child_count = 4;
        let confirmation = KillConfirmation {
            target: crowded_target,
            mode: KillMode::Force,
            requirement: ConfirmationRequirement::ForceWord,
            input: "for".to_owned(),
            error: Some("keep typing".to_owned()),
        };

        let lines = confirmation_lines(&confirmation, Theme::from_environment(), 13);
        let text = lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(lines.len() <= 13, "emitted {} lines", lines.len());
        assert!(text.contains("Type force"), "{text}");
        assert!(text.contains("Input: for"), "{text}");
        assert!(text.contains("Error: keep typing"), "{text}");
        assert!(text.contains("Esc cancels."), "{text}");
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
        let text = confirmation_lines(&confirmation, Theme::from_environment(), 40)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("confirms force-kill"), "{text}");
        assert!(!text.contains("confirms normal termination"), "{text}");
    }
}
