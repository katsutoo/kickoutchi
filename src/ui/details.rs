//! The selected-row details: the panel down the side, and the bigger modal.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::app::App;
use crate::display::sanitize;
use crate::model::{
    ChildProcessSnapshot, DockerContainerPort, DockerPortContext, PermissionStatus, PortEntry,
    ProcessContext, Protocol,
};

use super::{field, theme::Theme};

const MISSING: &str = "-";
const PANEL_LINES_MAX: usize = 8;
const CHILDREN_DISPLAY_MAX: usize = 8;

pub(crate) fn render_panel(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let lines = app.selected_row().map_or_else(
        || empty_lines(theme),
        |entry| {
            panel_lines(
                entry,
                app.selected_process_context(),
                app.selected_process_context_loading(),
                theme,
            )
        },
    );
    let panel = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title("Details")
            .title_style(theme.title())
            .border_style(theme.border()),
    );
    frame.render_widget(panel, area);
}

pub(crate) fn render_modal(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let mut lines = app.selected_row().map_or_else(
        || empty_lines(theme),
        |entry| {
            modal_lines(
                entry,
                app.selected_process_context(),
                app.selected_process_context_loading(),
                theme,
            )
        },
    );
    lines.push(Line::raw(""));
    // The footer only mentions the dismiss key for this modal. `q` quitting is a
    // global thing already shown in the header and the help modal, so repeating
    // it here would just tempt people into quitting when all they wanted was to
    // close the panel.
    lines.push(Line::from(vec![
        Span::styled("Esc", theme.key()),
        Span::raw(" closes this modal."),
    ]));

    let modal = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title("Port Details")
            .title_style(theme.title())
            .border_style(theme.border()),
    );
    frame.render_widget(Clear, area);
    frame.render_widget(modal, area);
}

fn panel_lines(
    entry: &PortEntry,
    context: Option<&ProcessContext>,
    context_loading: bool,
    theme: Theme,
) -> Vec<Line<'static>> {
    let warning_or_permission = if entry.protected {
        Line::styled(
            "Warning: protected process, stronger confirmation required before termination.",
            theme.protected(),
        )
    } else {
        field("Permission", permission_text(entry.permission), theme)
    };

    let mut lines = vec![
        field(
            "PID",
            format!(
                "{} | Process: {}",
                optional_u32(entry.pid),
                sanitize_optional_str(entry.process_name.as_deref())
            ),
            theme,
        ),
        field(
            "Bind",
            format!(
                "{} {}:{} {} | {}",
                entry.protocol.label(),
                entry.local_addr,
                entry.local_port,
                entry.state.label(),
                entry.scope_label()
            ),
            theme,
        ),
    ];
    if let Some(text) = docker_panel_text(context) {
        lines.push(field("Docker", text, theme));
    }
    lines.extend([
        field("Parent", parent_text(entry), theme),
        field(
            "Children",
            children_text(entry, context, context_loading),
            theme,
        ),
        field("Path", path_text(entry), theme),
        field(
            "Command",
            sanitize_optional_str(entry.command_line.as_deref()),
            theme,
        ),
        warning_or_permission,
    ]);
    debug_assert!(lines.len() <= PANEL_LINES_MAX);
    lines
}

fn modal_lines(
    entry: &PortEntry,
    context: Option<&ProcessContext>,
    context_loading: bool,
    theme: Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        field("Protocol", entry.protocol.label().to_owned(), theme),
        field("Address", entry.local_addr.to_string(), theme),
        field("Port", entry.local_port.to_string(), theme),
        field("Scope", entry.scope_label().to_owned(), theme),
        field("State", entry.state.label().to_owned(), theme),
        field("PID", optional_u32(entry.pid), theme),
        field(
            "Process",
            sanitize_optional_str(entry.process_name.as_deref()),
            theme,
        ),
    ];

    if let Some(docker) = context.and_then(|context| context.docker.as_ref()) {
        lines.extend(docker_modal_lines(docker, theme));
    }

    lines.extend([
        field("Parent", parent_text(entry), theme),
        field(
            "Children",
            children_text(entry, context, context_loading),
            theme,
        ),
        field("User", user_text(context), theme),
        field("Permission", permission_text(entry.permission), theme),
    ]);

    if entry.protected {
        lines.push(Line::styled(
            "Protected process: stronger confirmation will be required before termination.",
            theme.protected(),
        ));
    }

    lines.push(field("Path", path_text(entry), theme));
    lines.push(field(
        "Command",
        sanitize_optional_str(entry.command_line.as_deref()),
        theme,
    ));

    lines
}

fn empty_lines(theme: Theme) -> Vec<Line<'static>> {
    vec![Line::styled("No open ports to show.", theme.muted())]
}

fn optional_u32(value: Option<u32>) -> String {
    value.map_or_else(|| MISSING.to_owned(), |value| value.to_string())
}

fn path_text(entry: &PortEntry) -> String {
    entry.executable_path.as_ref().map_or_else(
        || MISSING.to_owned(),
        |path| sanitize(&path.display().to_string()),
    )
}

fn sanitize_optional_str(value: Option<&str>) -> String {
    value.map_or_else(|| MISSING.to_owned(), sanitize)
}

fn parent_text(entry: &PortEntry) -> String {
    match (entry.parent_process_name.as_deref(), entry.parent_pid) {
        (Some(name), Some(pid)) => format!("{} (PID {pid})", sanitize(name)),
        (Some(name), None) => sanitize(name),
        (None, Some(pid)) => format!("PID {pid}"),
        (None, None) => MISSING.to_owned(),
    }
}

fn children_text(
    entry: &PortEntry,
    context: Option<&ProcessContext>,
    context_loading: bool,
) -> String {
    if entry.pid.is_none() {
        return "unavailable (missing PID)".to_owned();
    }

    if context_loading {
        return "loading".to_owned();
    }

    let Some(context) = context else {
        return "open details to load".to_owned();
    };
    children_snapshot_text(&context.children)
}

fn children_snapshot_text(snapshot: &ChildProcessSnapshot) -> String {
    if snapshot.children.is_empty() {
        return "none".to_owned();
    }

    let visible = snapshot
        .children
        .iter()
        .take(CHILDREN_DISPLAY_MAX)
        .map(|child| {
            let name = child
                .process_name
                .as_deref()
                .map_or_else(|| "<unknown>".to_owned(), sanitize);
            format!("PID {} ({name})", child.pid)
        })
        .collect::<Vec<_>>()
        .join(", ");
    let hidden = snapshot.children.len().saturating_sub(CHILDREN_DISPLAY_MAX);
    let suffix = if snapshot.truncated {
        " (truncated)".to_owned()
    } else if hidden > 0 {
        format!(" (+{hidden} more)")
    } else {
        String::new()
    };
    format!("{} ({visible}){suffix}", snapshot.children.len())
}

fn docker_panel_text(context: Option<&ProcessContext>) -> Option<String> {
    context
        .and_then(|context| context.docker.as_ref())
        .map(docker_summary_text)
}

fn docker_modal_lines(docker: &DockerPortContext, theme: Theme) -> Vec<Line<'static>> {
    let mut lines = vec![field("Docker", docker_summary_text(docker), theme)];
    if let Some(container) = docker.single_container() {
        if let Some(compose) = docker_compose_text(container) {
            lines.push(field("Compose", compose, theme));
        }
        lines.push(field(
            "Docker stop",
            sanitize(&container.stop_command()),
            theme,
        ));
    } else {
        lines.push(field(
            "Docker stop",
            "ambiguous; inspect with docker ps".to_owned(),
            theme,
        ));
    }
    lines
}

fn docker_summary_text(docker: &DockerPortContext) -> String {
    if let Some(container) = docker.single_container() {
        return docker_container_summary(container);
    }

    let suffix = if docker.truncated { " or more" } else { "" };
    format!("{}{} matching containers", docker.containers.len(), suffix)
}

fn docker_container_summary(container: &DockerContainerPort) -> String {
    format!(
        "{} {}->{}{}",
        sanitize(&docker_container_label(container)),
        container.host_port,
        container.container_port,
        protocol_suffix(container.protocol),
    )
}

fn docker_container_label(container: &DockerContainerPort) -> String {
    match (
        container.compose_project.as_deref(),
        container.compose_service.as_deref(),
    ) {
        (Some(project), Some(service)) => format!("{project}/{service} ({})", container.name),
        (Some(project), None) => format!("{project} ({})", container.name),
        (None, Some(service)) => format!("{service} ({})", container.name),
        (None, None) => container.name.clone(),
    }
}

fn docker_compose_text(container: &DockerContainerPort) -> Option<String> {
    match (
        container.compose_project.as_deref(),
        container.compose_service.as_deref(),
    ) {
        (Some(project), Some(service)) => Some(format!("{project}/{service}")),
        (Some(project), None) => Some(project.to_owned()),
        (None, Some(service)) => Some(service.to_owned()),
        (None, None) => None,
    }
    .map(|text| sanitize(&text))
}

fn protocol_suffix(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "/tcp",
        Protocol::Udp => "/udp",
    }
}

fn user_text(context: Option<&ProcessContext>) -> String {
    context
        .and_then(|context| context.owner_uid)
        .map_or_else(|| MISSING.to_owned(), |uid| format!("uid {uid}"))
}

fn permission_text(permission: PermissionStatus) -> String {
    match permission {
        PermissionStatus::Full => "full".to_owned(),
        PermissionStatus::Partial => "partial (metadata restricted)".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use super::{
        MISSING, PANEL_LINES_MAX, children_text, docker_panel_text, docker_summary_text,
        panel_lines, parent_text, permission_text, user_text,
    };
    use crate::model::{
        ChildProcess, ChildProcessSnapshot, DockerContainerPort, DockerPortContext,
        PermissionStatus, Platform, PortEntry, ProcessContext, Protocol, SocketState,
    };
    use crate::ui::theme::Theme;

    fn entry() -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: Some(18_422),
            process_name: Some("node".to_owned()),
            executable_path: Some(PathBuf::from("/usr/bin/node")),
            command_line: Some("node server.js".to_owned()),
            parent_pid: Some(18_001),
            parent_process_name: Some("cursor-agent".to_owned()),
            child_pids: vec![18_430, 18_431],
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
        }
    }

    #[test]
    fn panel_summary_fits_the_default_details_area() {
        let context = ProcessContext::default();
        let lines = panel_lines(&entry(), Some(&context), false, Theme::from_environment());

        assert!(lines.len() <= PANEL_LINES_MAX);
    }

    #[test]
    fn docker_context_adds_bounded_details_without_replacing_os_metadata() {
        let docker = DockerPortContext {
            containers: vec![DockerContainerPort {
                id: "a762a2b37a1d".to_owned(),
                name: "postgres-dev".to_owned(),
                compose_project: Some("swamp".to_owned()),
                compose_service: Some("db".to_owned()),
                host_port: 5432,
                container_port: 5432,
                protocol: Protocol::Tcp,
            }],
            truncated: false,
        };
        let context = ProcessContext {
            docker: Some(docker.clone()),
            ..ProcessContext::default()
        };
        let lines = panel_lines(&entry(), Some(&context), false, Theme::from_environment());

        assert!(lines.len() <= PANEL_LINES_MAX);
        assert_eq!(
            docker_panel_text(Some(&context)).as_deref(),
            Some("swamp/db (postgres-dev) 5432->5432/tcp"),
        );
        assert_eq!(
            docker_summary_text(&docker),
            "swamp/db (postgres-dev) 5432->5432/tcp",
        );
    }

    #[test]
    fn parent_text_covers_partial_metadata() {
        let mut row = entry();
        assert_eq!(parent_text(&row), "cursor-agent (PID 18001)");

        row.parent_process_name = None;
        assert_eq!(parent_text(&row), "PID 18001");

        row.parent_pid = None;
        assert_eq!(parent_text(&row), MISSING);
    }

    #[test]
    fn children_text_distinguishes_unavailable_none_and_named_children() {
        let mut row = entry();
        let context = ProcessContext {
            owner_uid: Some(1000),
            process_start_time_marker: Some(55),
            children: ChildProcessSnapshot {
                children: vec![
                    ChildProcess {
                        pid: 18_430,
                        process_name: Some("worker".to_owned()),
                    },
                    ChildProcess {
                        pid: 18_431,
                        process_name: None,
                    },
                ],
                truncated: false,
            },
            docker: None,
        };

        assert_eq!(
            children_text(&row, Some(&context), false),
            "2 (PID 18430 (worker), PID 18431 (<unknown>))"
        );
        assert_eq!(user_text(Some(&context)), "uid 1000");

        row.pid = None;
        assert_eq!(
            children_text(&row, Some(&context), false),
            "unavailable (missing PID)"
        );

        row.pid = Some(18_422);
        assert_eq!(
            children_text(&row, Some(&ProcessContext::default()), false),
            "none"
        );
        assert_eq!(children_text(&row, None, true), "loading");
        assert_eq!(children_text(&row, None, false), "open details to load");
    }

    #[test]
    fn permission_text_explains_partial_metadata() {
        assert_eq!(permission_text(PermissionStatus::Full), "full");
        assert_eq!(
            permission_text(PermissionStatus::Partial),
            "partial (metadata restricted)"
        );
    }
}
