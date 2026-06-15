//! TUI color and style choices.
//!
//! The UI must remain useful without color. `NO_COLOR` disables foreground and
//! background colors while keeping safe non-color emphasis such as bold and
//! reverse video for selection.

use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Theme {
    no_color: bool,
}

impl Theme {
    pub(crate) fn from_environment() -> Self {
        Self {
            no_color: std::env::var_os("NO_COLOR").is_some(),
        }
    }

    pub(crate) fn title(self) -> Style {
        self.fg(Color::Cyan).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn border(self) -> Style {
        self.fg(Color::Reset)
    }

    pub(crate) fn table_header(self) -> Style {
        self.fg(Color::Blue).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn selected(self) -> Style {
        if self.no_color {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        }
    }

    pub(crate) fn protected(self) -> Style {
        self.fg(Color::Red).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn warning(self) -> Style {
        self.fg(Color::Yellow).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn muted(self) -> Style {
        self.fg(Color::Reset)
    }

    pub(crate) fn label(self) -> Style {
        self.fg(Color::Blue).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn key(self) -> Style {
        self.fg(Color::Green).add_modifier(Modifier::BOLD)
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn status(self) -> Style {
        Style::default()
            .add_modifier(Modifier::REVERSED)
            .add_modifier(Modifier::BOLD)
    }

    fn fg(self, color: Color) -> Style {
        if self.no_color {
            Style::default()
        } else {
            Style::default().fg(color)
        }
    }
}
