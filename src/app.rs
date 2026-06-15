//! TUI application state and state transitions.
//!
//! The app owns the latest successful collected snapshot, the filtered table
//! view, selection, search/sort state, modal state, and status metadata.

use std::time::{Duration, Instant};

use crate::collector;
#[cfg(test)]
use crate::collector::{Collector, FakeCollector};
use crate::config::Config;
use crate::input::Action;
use crate::model::{PortEntry, Protocol, SortMode, mark_protected};
use crate::query::{self, FILTER_TEXT_MAX_BYTES, QueryOptions};

/// Modal currently covering the main table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Modal {
    None,
    Details,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RowKey {
    pid: Option<u32>,
    protocol: Protocol,
    local_addr: std::net::IpAddr,
    local_port: u16,
}

impl From<&PortEntry> for RowKey {
    fn from(entry: &PortEntry) -> Self {
        Self {
            pid: entry.pid,
            protocol: entry.protocol,
            local_addr: entry.local_addr,
            local_port: entry.local_port,
        }
    }
}

/// Mutable TUI state.
#[derive(Debug)]
pub(crate) struct App {
    all_rows: Vec<PortEntry>,
    rows: Vec<PortEntry>,
    selected_index: Option<usize>,
    filter_text: String,
    search_mode: bool,
    sort_mode: SortMode,
    hide_system_processes: bool,
    protected_processes: Vec<String>,
    last_successful_refresh: Option<Instant>,
    last_refresh_attempt: Instant,
    modal: Modal,
    latest_error: Option<String>,
    filter_error: Option<String>,
    should_quit: bool,
}

impl App {
    /// Build the TUI app from the platform collector.
    pub(crate) fn new(config: &Config) -> Self {
        let mut app = Self::empty(config, Instant::now());
        app.refresh();
        app
    }

    #[cfg(test)]
    pub(crate) fn new_fake(config: &Config) -> Self {
        let rows = FakeCollector
            .collect()
            .expect("fake collection cannot fail");
        Self::from_rows(rows, config)
    }

    #[cfg(test)]
    fn from_rows(rows: Vec<PortEntry>, config: &Config) -> Self {
        let mut app = Self::empty(config, Instant::now());
        app.apply_successful_snapshot(rows, Instant::now());
        app
    }

    fn empty(config: &Config, now: Instant) -> Self {
        Self {
            all_rows: Vec::new(),
            rows: Vec::new(),
            selected_index: None,
            filter_text: String::new(),
            search_mode: false,
            sort_mode: config.default_sort,
            hide_system_processes: config.hide_system_processes,
            protected_processes: config.protected_processes.clone(),
            last_successful_refresh: None,
            last_refresh_attempt: now,
            modal: Modal::None,
            latest_error: None,
            filter_error: None,
            should_quit: false,
        }
    }

    pub(crate) fn refresh(&mut self) {
        let result = collector::collect_ports();
        self.finish_refresh_attempt(result, Instant::now());
    }

    fn finish_refresh_attempt(
        &mut self,
        result: Result<Vec<PortEntry>, collector::CollectorError>,
        completed_at: Instant,
    ) {
        self.last_refresh_attempt = completed_at;
        match result {
            Ok(rows) => self.apply_successful_snapshot(rows, completed_at),
            Err(error) => self.latest_error = Some(error.to_string()),
        }
    }

    pub(crate) fn refresh_due(&self, refresh_interval: Duration) -> bool {
        self.refresh_due_at(Instant::now(), refresh_interval)
    }

    pub(crate) fn time_until_refresh(&self, refresh_interval: Duration) -> Duration {
        self.time_until_refresh_at(Instant::now(), refresh_interval)
    }

    fn refresh_due_at(&self, now: Instant, refresh_interval: Duration) -> bool {
        now.saturating_duration_since(self.last_refresh_attempt) >= refresh_interval
    }

    fn time_until_refresh_at(&self, now: Instant, refresh_interval: Duration) -> Duration {
        refresh_interval.saturating_sub(now.saturating_duration_since(self.last_refresh_attempt))
    }

    pub(crate) fn rows(&self) -> &[PortEntry] {
        &self.rows
    }

    pub(crate) fn total_row_count(&self) -> usize {
        self.all_rows.len()
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

    pub(crate) fn search_mode(&self) -> bool {
        self.search_mode
    }

    pub(crate) fn sort_mode(&self) -> SortMode {
        self.sort_mode
    }

    pub(crate) fn refresh_age(&self) -> Option<Duration> {
        self.last_successful_refresh
            .map(|instant| instant.elapsed())
    }

    pub(crate) fn modal(&self) -> Modal {
        self.modal
    }

    pub(crate) fn latest_error(&self) -> Option<&str> {
        self.latest_error.as_deref()
    }

    pub(crate) fn filter_error(&self) -> Option<&str> {
        self.filter_error.as_deref()
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
            Action::Refresh => self.refresh(),
            Action::StartSearch => self.search_mode = true,
            Action::SearchAppend(ch) => self.append_search_char(ch),
            Action::SearchBackspace => self.backspace_search(),
            Action::FinishSearch => self.search_mode = false,
            Action::CancelSearch => self.cancel_search(),
            Action::CycleSort => self.cycle_sort(),
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
            self.search_mode = false;
            self.modal = Modal::Details;
        }
    }

    fn apply_successful_snapshot(&mut self, mut rows: Vec<PortEntry>, now: Instant) {
        mark_protected(&mut rows, &self.protected_processes);
        self.all_rows = rows;
        self.last_successful_refresh = Some(now);
        self.latest_error = None;
        self.rebuild_visible_rows();
    }

    fn rebuild_visible_rows(&mut self) {
        let selected_key = self.selected_row().map(RowKey::from);
        let fallback_index = self.selected_index.unwrap_or(0);

        match query::query_entries(
            &self.all_rows,
            QueryOptions {
                port: None,
                process: None,
                filter_text: &self.filter_text,
                sort_mode: self.sort_mode,
                hide_system_processes: self.hide_system_processes,
            },
        ) {
            Ok(result) => {
                self.rows = result.entries;
                self.filter_error = None;
            }
            Err(error) => {
                self.rows.clear();
                self.filter_error = Some(error.to_string());
            }
        }

        self.selected_index = preserved_selection(&self.rows, selected_key, fallback_index);
    }

    fn append_search_char(&mut self, ch: char) {
        if !self.search_mode {
            return;
        }
        if self.filter_text.len() + ch.len_utf8() > FILTER_TEXT_MAX_BYTES {
            return;
        }
        self.filter_text.push(ch);
        self.rebuild_visible_rows();
    }

    fn backspace_search(&mut self) {
        if !self.search_mode {
            return;
        }
        self.filter_text.pop();
        self.rebuild_visible_rows();
    }

    fn cancel_search(&mut self) {
        self.search_mode = false;
        if !self.filter_text.is_empty() {
            self.filter_text.clear();
            self.rebuild_visible_rows();
        }
    }

    fn cycle_sort(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.rebuild_visible_rows();
    }
}

fn preserved_selection(
    rows: &[PortEntry],
    selected_key: Option<RowKey>,
    fallback_index: usize,
) -> Option<usize> {
    if rows.is_empty() {
        return None;
    }
    if let Some(key) = selected_key
        && let Some(index) = rows.iter().position(|row| RowKey::from(row) == key)
    {
        return Some(index);
    }
    Some(fallback_index.min(rows.len() - 1))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use super::{App, Modal};
    use crate::config::Config;
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
        let config = Config {
            default_sort: SortMode::Port,
            protected_processes: vec!["postgres".to_owned()],
            ..Config::default()
        };
        App::from_rows(rows, &config)
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
    fn search_actions_filter_and_clear_rows() {
        let mut app = app_with_rows(vec![entry(3000, Some("node")), entry(5173, Some("vite"))]);

        app.apply_action(Action::StartSearch);
        app.apply_action(Action::SearchAppend('v'));
        app.apply_action(Action::SearchAppend('i'));

        assert!(app.search_mode());
        assert_eq!(app.filter_text(), "vi");
        assert_eq!(app.rows().len(), 1);
        assert_eq!(app.rows()[0].local_port, 5173);

        app.apply_action(Action::CancelSearch);

        assert!(!app.search_mode());
        assert_eq!(app.filter_text(), "");
        assert_eq!(app.rows().len(), 2);
    }

    #[test]
    fn sort_cycle_preserves_selected_row_when_possible() {
        let mut app = app_with_rows(vec![entry(3000, Some("zed")), entry(5173, Some("alpha"))]);
        app.apply_action(Action::MoveDown);
        assert_eq!(app.selected_row().map(|row| row.local_port), Some(5173));

        app.apply_action(Action::CycleSort);
        app.apply_action(Action::CycleSort);
        app.apply_action(Action::CycleSort);

        assert_eq!(app.sort_mode(), SortMode::Process);
        assert_eq!(app.selected_row().map(|row| row.local_port), Some(5173));
    }

    #[test]
    fn successful_refresh_preserves_selection_by_row_identity() {
        let mut app = app_with_rows(vec![entry(3000, Some("node")), entry(5173, Some("vite"))]);
        app.apply_action(Action::MoveDown);
        let refreshed = vec![entry(5173, Some("vite")), entry(3000, Some("node"))];

        app.apply_successful_snapshot(refreshed, Instant::now());

        assert_eq!(app.selected_row().map(|row| row.local_port), Some(5173));
    }

    #[test]
    fn refresh_moves_selection_to_nearest_row_when_selected_row_disappears() {
        let mut app = app_with_rows(vec![
            entry(3000, Some("node")),
            entry(5173, Some("vite")),
            entry(8000, Some("python")),
        ]);
        app.apply_action(Action::MoveDown);
        let refreshed = vec![entry(3000, Some("node")), entry(8000, Some("python"))];

        app.apply_successful_snapshot(refreshed, Instant::now());

        assert_eq!(app.selected_index(), Some(1));
        assert_eq!(app.selected_row().map(|row| row.local_port), Some(8000));
    }

    #[test]
    fn collection_error_keeps_last_successful_rows_visible() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.latest_error = Some("cannot read /proc/net/tcp".to_owned());
        app.rebuild_visible_rows();

        assert_eq!(app.rows().len(), 1);
        assert_eq!(app.latest_error(), Some("cannot read /proc/net/tcp"));
    }

    #[test]
    fn refresh_deadline_uses_completed_attempt_time() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        let completed_at = Instant::now();
        app.last_refresh_attempt = completed_at
            .checked_sub(Duration::from_secs(3))
            .expect("test timestamp remains representable");

        assert!(app.refresh_due_at(completed_at, Duration::from_secs(3)));
        assert_eq!(
            app.time_until_refresh_at(completed_at, Duration::from_secs(3)),
            Duration::ZERO
        );

        app.finish_refresh_attempt(Ok(vec![entry(3000, Some("node"))]), completed_at);

        assert!(!app.refresh_due_at(completed_at, Duration::from_secs(3)));
        assert_eq!(
            app.time_until_refresh_at(completed_at, Duration::from_secs(3)),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn protected_names_are_marked_from_config() {
        let app = app_with_rows(vec![entry(5432, Some("postgres"))]);

        assert!(app.rows()[0].protected);
    }
}
