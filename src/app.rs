//! TUI application state and state transitions.
//!
//! The app owns the latest collected snapshot, selection, modal state, and
//! status metadata. Refresh and filtering arrive later, but the state shape
//! already has the fields those features mutate so the UI does not need to be
//! redesigned in Phase 4.

use std::time::{Duration, Instant};

use crate::collector;
#[cfg(test)]
use crate::collector::{Collector, FakeCollector};
use crate::config::Config;
use crate::input::Action;
use crate::model::{PortEntry, SortMode, mark_protected, sort_entries};

/// Modal currently covering the main table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Modal {
    None,
    Details,
    Help,
}

/// Mutable TUI state.
#[derive(Debug)]
pub(crate) struct App {
    rows: Vec<PortEntry>,
    selected_index: Option<usize>,
    filter_text: String,
    sort_mode: SortMode,
    last_refresh: Instant,
    modal: Modal,
    latest_error: Option<String>,
    should_quit: bool,
}

impl App {
    /// Build the TUI app from the platform collector.
    pub(crate) fn new(config: &Config) -> Self {
        let (rows, latest_error) = match collector::collect_ports() {
            Ok(rows) => (rows, None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        Self::from_rows_with_error(
            rows,
            config.default_sort,
            &config.protected_processes,
            latest_error,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_fake(config: &Config) -> Self {
        let rows = FakeCollector
            .collect()
            .expect("fake collection cannot fail");
        Self::from_rows(rows, config.default_sort, &config.protected_processes)
    }

    #[cfg(test)]
    fn from_rows(
        rows: Vec<PortEntry>,
        sort_mode: SortMode,
        protected_processes: &[String],
    ) -> Self {
        Self::from_rows_with_error(rows, sort_mode, protected_processes, None)
    }

    fn from_rows_with_error(
        mut rows: Vec<PortEntry>,
        sort_mode: SortMode,
        protected_processes: &[String],
        latest_error: Option<String>,
    ) -> Self {
        mark_protected(&mut rows, protected_processes);
        sort_entries(&mut rows, sort_mode);
        let selected_index = if rows.is_empty() { None } else { Some(0) };

        Self {
            rows,
            selected_index,
            filter_text: String::new(),
            sort_mode,
            last_refresh: Instant::now(),
            modal: Modal::None,
            latest_error,
            should_quit: false,
        }
    }

    pub(crate) fn rows(&self) -> &[PortEntry] {
        &self.rows
    }

    pub(crate) fn selected_index(&self) -> Option<usize> {
        self.selected_index
    }

    pub(crate) fn selected_row(&self) -> Option<&PortEntry> {
        self.selected_index.and_then(|index| self.rows.get(index))
    }

    pub(crate) fn filter_text(&self) -> &str {
        &self.filter_text
    }

    pub(crate) fn sort_mode(&self) -> SortMode {
        self.sort_mode
    }

    pub(crate) fn refresh_age(&self) -> Duration {
        self.last_refresh.elapsed()
    }

    pub(crate) fn modal(&self) -> Modal {
        self.modal
    }

    pub(crate) fn latest_error(&self) -> Option<&str> {
        self.latest_error.as_deref()
    }

    pub(crate) fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub(crate) fn apply_action(&mut self, action: Action) {
        match action {
            Action::MoveDown => self.select_next(),
            Action::MoveUp => self.select_previous(),
            Action::OpenDetails => self.open_details(),
            Action::OpenHelp => self.modal = Modal::Help,
            Action::CloseModal => self.modal = Modal::None,
            Action::Quit => self.should_quit = true,
            Action::Noop => {}
        }
    }

    fn select_next(&mut self) {
        let Some(index) = self.selected_index else {
            return;
        };
        let max_index = self.rows.len().saturating_sub(1);
        self.selected_index = Some((index + 1).min(max_index));
    }

    fn select_previous(&mut self) {
        let Some(index) = self.selected_index else {
            return;
        };
        self.selected_index = Some(index.saturating_sub(1));
    }

    fn open_details(&mut self) {
        if self.selected_row().is_some() {
            self.modal = Modal::Details;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{App, Modal};
    use crate::input::Action;
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState, SortMode};

    fn entry(port: u16, name: Option<&str>) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid: Some(u32::from(port)),
            process_name: name.map(str::to_owned),
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

    fn app_with_rows(rows: Vec<PortEntry>) -> App {
        App::from_rows(rows, SortMode::Port, &["postgres".to_owned()])
    }

    #[test]
    fn starts_sorted_and_selects_first_row() {
        let app = app_with_rows(vec![entry(5173, Some("vite")), entry(3000, Some("node"))]);

        assert_eq!(app.rows()[0].local_port, 3000);
        assert_eq!(app.selected_index(), Some(0));
        assert_eq!(app.selected_row().map(|row| row.local_port), Some(3000));
    }

    #[test]
    fn selection_movement_is_bounded() {
        let mut app = app_with_rows(vec![entry(1, Some("one")), entry(2, Some("two"))]);

        app.apply_action(Action::MoveUp);
        assert_eq!(app.selected_index(), Some(0));

        app.apply_action(Action::MoveDown);
        assert_eq!(app.selected_index(), Some(1));

        app.apply_action(Action::MoveDown);
        assert_eq!(app.selected_index(), Some(1));
    }

    #[test]
    fn empty_rows_have_no_selection_and_no_details_modal() {
        let mut app = app_with_rows(Vec::new());

        assert_eq!(app.selected_index(), None);
        app.apply_action(Action::MoveDown);
        app.apply_action(Action::OpenDetails);
        assert_eq!(app.modal(), Modal::None);
    }

    #[test]
    fn modal_and_quit_actions_update_state() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

        app.apply_action(Action::OpenDetails);
        assert_eq!(app.modal(), Modal::Details);

        app.apply_action(Action::CloseModal);
        assert_eq!(app.modal(), Modal::None);

        app.apply_action(Action::OpenHelp);
        assert_eq!(app.modal(), Modal::Help);

        app.apply_action(Action::Quit);
        assert!(app.should_quit());
    }

    #[test]
    fn protected_names_are_marked_from_config() {
        let app = app_with_rows(vec![entry(5432, Some("postgres"))]);

        assert!(app.rows()[0].protected);
    }
}
