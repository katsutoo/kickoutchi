//! Colors and styles for the TUI.
//!
//! The UI has to stay usable with no color at all. `NO_COLOR` drops foreground
//! and background colors but keeps the color-free emphasis — bold, and reverse
//! video for the selected row.

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

    #[expect(
        clippy::unused_self,
        reason = "every Theme accessor takes self so callers stay uniform when a style becomes palette-dependent"
    )]
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
