//! The "wait, are you sure you want to kill this?" modal.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::app::{self, App, KillConfirmation};
use crate::display::sanitize;
use crate::process::ConfirmationRequirement;

use super::{field, theme::Theme};

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
