//! The TUI's state, and every way it's allowed to change.
//!
//! `App` holds the latest good snapshot, the filtered table view, the selection,
//! search/sort state, which modal is open, and the bits of status we show.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use crate::collector;
#[cfg(test)]
use crate::collector::{Collector, FakeCollector};
use crate::command;
use crate::config::Config;
use crate::input::Action;
use crate::model::{PortEntry, ProcessContext, Protocol, SortMode};
use crate::platform;
use crate::process::{
    self, CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, KillMode, KillTarget,
    TerminationOutcome,
};
use crate::protection::mark_protected;
use crate::query::{self, FILTER_TEXT_MAX_BYTES, QueryOptions};

type RefreshResult = Result<Vec<PortEntry>, collector::CollectorError>;

#[derive(Debug)]
struct RefreshWorker {
    receiver: Receiver<RefreshResult>,
    stale: bool,
}

/// Whichever modal is currently sitting over the main table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Modal {
    None,
    Details,
    Help,
    ConfirmKill,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KillConfirmation {
    pub(crate) target: KillTarget,
    pub(crate) mode: KillMode,
    pub(crate) requirement: ConfirmationRequirement,
    pub(crate) input: String,
    pub(crate) error: Option<String>,
}

impl KillConfirmation {
    fn new(target: KillTarget, mode: KillMode, requirement: ConfirmationRequirement) -> Self {
        Self {
            target,
            mode,
            requirement,
            input: String::new(),
            error: None,
        }
    }
}

/// How strict force-kill confirmation should be, taken from
/// `Config::confirm_force_kill`.
///
/// A named two-state type instead of yet another `bool` on `App`: it keeps the
/// struct's bool count down (clippy `struct_excessive_bools`) and spells out the
/// intent at the call site. It only picks *which* confirmation the force path
/// uses — never whether the TUI confirms at all. (It always does.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForceKillConfirmation {
    TypedForce,
    YesOnly,
}

impl ForceKillConfirmation {
    fn from_config(confirm_force_kill: bool) -> Self {
        if confirm_force_kill {
            Self::TypedForce
        } else {
            Self::YesOnly
        }
    }

    fn confirm_force_kill(self) -> bool {
        self == Self::TypedForce
    }
}

/// The mutable guts of the TUI.
#[derive(Debug)]
pub(crate) struct App {
    all_rows: Vec<PortEntry>,
    rows: Vec<PortEntry>,
    selected_index: Option<usize>,
    filter_text: String,
    search_mode: bool,
    sort_mode: SortMode,
    hide_system_processes: bool,
    force_kill_confirmation: ForceKillConfirmation,
    protected_processes: Vec<String>,
    selected_context_key: Option<RowKey>,
    selected_process_context: Option<ProcessContext>,
    kill_confirmation: Option<KillConfirmation>,
    kill_status: Option<String>,
    refresh_worker: Option<RefreshWorker>,
    last_successful_refresh: Option<Instant>,
    last_refresh_attempt: Instant,
    modal: Modal,
    latest_error: Option<String>,
    filter_error: Option<String>,
    should_quit: bool,
}

impl App {
    /// Build the app with its first snapshot already populated.
    ///
    /// The initial collect runs on this thread, not the background worker: the
    /// event loop parks in `event::poll` for a whole tick, and a worker finishing
    /// does not wake it, so an async first load would leave the table blank for
    /// ~one tick on every launch. Only this initial load blocks — manual `r` and
    /// the auto-refresh tick still go through the off-thread [`App::refresh`].
    pub(crate) fn new(config: &Config) -> Self {
        let mut app = Self::empty(config, Instant::now());
        app.refresh_blocking();
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
            force_kill_confirmation: ForceKillConfirmation::from_config(config.confirm_force_kill),
            protected_processes: config.protected_processes.clone(),
            selected_context_key: None,
            selected_process_context: None,
            kill_confirmation: None,
            kill_status: None,
            refresh_worker: None,
            last_successful_refresh: None,
            last_refresh_attempt: now,
            modal: Modal::None,
            latest_error: None,
            filter_error: None,
            should_quit: false,
        }
    }

    /// Collect one snapshot on the calling thread. Used only for the initial
    /// load in [`App::new`]; every refresh after that runs through the worker.
    fn refresh_blocking(&mut self) {
        self.finish_refresh_attempt(collector::collect_ports(), Instant::now());
    }

    pub(crate) fn refresh(&mut self) {
        if self.refresh_worker.is_some() {
            return;
        }

        // One refresh worker at a time. The Linux collector may walk every
        // process fd directory to preserve shared-socket correctness; doing that
        // off the render loop keeps key handling out of the swamp mud without
        // letting scans pile up behind it.
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name("kickoutchi-refresh".to_owned())
            .spawn(move || {
                let _ = sender.send(collector::collect_ports());
            }) {
            Ok(_handle) => {
                self.refresh_worker = Some(RefreshWorker {
                    receiver,
                    stale: false,
                });
            }
            Err(error) => {
                self.last_refresh_attempt = Instant::now();
                self.latest_error = Some(format!("starting refresh worker failed: {error}"));
            }
        }
    }

    pub(crate) fn poll_refresh(&mut self) {
        let Some(worker) = self.refresh_worker.as_ref() else {
            return;
        };

        let result = match worker.receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(collector::CollectorError::WorkerExited),
        };
        let stale = worker.stale;

        self.refresh_worker = None;
        if !stale {
            self.finish_refresh_attempt(result, Instant::now());
        }
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
        if self.modal == Modal::ConfirmKill {
            return false;
        }
        if self.refresh_worker.is_some() {
            return false;
        }
        now.saturating_duration_since(self.last_refresh_attempt) >= refresh_interval
    }

    fn time_until_refresh_at(&self, now: Instant, refresh_interval: Duration) -> Duration {
        if self.modal == Modal::ConfirmKill {
            return refresh_interval;
        }
        if self.refresh_worker.is_some() {
            return refresh_interval;
        }
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

    pub(crate) fn selected_process_context(&self) -> Option<&ProcessContext> {
        let selected_key = self.selected_row().map(RowKey::from)?;
        if self.selected_context_key == Some(selected_key) {
            self.selected_process_context.as_ref()
        } else {
            None
        }
    }

    pub(crate) fn kill_confirmation(&self) -> Option<&KillConfirmation> {
        self.kill_confirmation.as_ref()
    }

    pub(crate) fn kill_status(&self) -> Option<&str> {
        self.kill_status.as_deref()
    }

    /// Whether a background refresh worker is still in flight. Test-only: the
    /// status bar deliberately does not surface refresh progress to the user.
    #[cfg(test)]
    pub(crate) fn refresh_in_progress(&self) -> bool {
        self.refresh_worker.is_some()
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
            Action::RequestTerminate => self.request_kill(KillMode::Terminate),
            Action::RequestForceKill => self.request_kill(KillMode::Force),
            Action::SubmitKillConfirmation => self.submit_kill_confirmation(),
            Action::KillInputAppend(ch) => self.append_kill_input(ch),
            Action::KillInputBackspace => self.backspace_kill_input(),
            Action::CancelKill => self.cancel_kill_confirmation(),
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
            self.load_selected_process_context();
            self.modal = Modal::Details;
        }
    }

    fn request_kill(&mut self, mode: KillMode) {
        self.search_mode = false;
        self.kill_status = None;

        let Some(entry) = self.selected_row().cloned() else {
            self.kill_status = Some("no selected process to terminate".to_owned());
            return;
        };
        let Some(pid) = entry.pid else {
            self.kill_status = Some("selected row has no PID; cannot terminate".to_owned());
            return;
        };
        if let Some(reason) = process::unsafe_pid_reason(pid) {
            self.kill_status = Some(format!("unsafe PID blocked: {}", reason.message()));
            return;
        }

        let context = platform::collect_process_context(pid);
        self.selected_context_key = Some(RowKey::from(&entry));
        self.selected_process_context = Some(context.clone());

        let target = KillTarget::from_entries(
            pid,
            self.all_rows.iter().filter(|row| row.pid == Some(pid)),
            Some(&context),
        );
        // `yes` is always false here: the interactive TUI has no `--yes`, so the
        // shared policy can only ever hand back `Some(_)` (a confirmation to
        // satisfy). The `None` arm is the CLI's `--yes` "skip confirmation" path
        // and can't happen from the TUI — but we still map it to a require-`y`
        // prompt, so if that policy ever changes the worst case is "asks again",
        // never "kills without asking".
        let requirement = match process::confirmation_requirement(
            target.protected,
            target.platform,
            mode,
            false,
            self.force_kill_confirmation.confirm_force_kill(),
        ) {
            Ok(Some(requirement)) => requirement,
            Ok(None) => ConfirmationRequirement::Yes,
            Err(outcome) => {
                self.kill_status = Some(termination_status_line(&target, mode, &outcome));
                return;
            }
        };

        self.kill_confirmation = Some(KillConfirmation::new(target, mode, requirement));
        self.modal = Modal::ConfirmKill;
    }

    fn append_kill_input(&mut self, ch: char) {
        let Some(requirement) = self
            .kill_confirmation
            .as_ref()
            .map(|confirmation| confirmation.requirement)
        else {
            return;
        };

        if requirement == ConfirmationRequirement::Yes {
            if ch == 'y' || ch == 'Y' {
                self.execute_kill_confirmation();
            } else if ch == 'n' || ch == 'N' {
                self.cancel_kill_confirmation();
            } else if let Some(confirmation) = self.kill_confirmation.as_mut() {
                confirmation.error = Some("press y to confirm or Esc to cancel".to_owned());
            }
            return;
        }

        let Some(confirmation) = self.kill_confirmation.as_mut() else {
            return;
        };
        if confirmation.input.len() + ch.len_utf8() > CONFIRMATION_INPUT_MAX_BYTES {
            confirmation.error = Some(format!(
                "confirmation input is capped at {CONFIRMATION_INPUT_MAX_BYTES} bytes",
            ));
            return;
        }
        confirmation.input.push(ch);
        confirmation.error = None;
    }

    fn backspace_kill_input(&mut self) {
        let Some(confirmation) = self.kill_confirmation.as_mut() else {
            return;
        };
        confirmation.input.pop();
        confirmation.error = None;
    }

    fn submit_kill_confirmation(&mut self) {
        let Some(confirmation) = self.kill_confirmation.as_ref() else {
            return;
        };
        if process::confirmation_input_matches(
            &confirmation.input,
            &confirmation.target,
            confirmation.requirement,
        ) {
            self.execute_kill_confirmation();
            return;
        }

        if let Some(confirmation) = self.kill_confirmation.as_mut() {
            confirmation.error = Some(match confirmation.requirement {
                ConfirmationRequirement::Yes => "press y to confirm or Esc to cancel".to_owned(),
                ConfirmationRequirement::ForceWord => format!(
                    "type force and press Enter to confirm {}",
                    confirmation
                        .mode
                        .delivery_label(confirmation.target.platform),
                ),
                ConfirmationRequirement::ProtectedProcess => format!(
                    "type PID {} or process name {} to confirm",
                    confirmation.target.pid,
                    confirmation.target.process_name_or_unknown(),
                ),
            });
        }
    }

    fn cancel_kill_confirmation(&mut self) {
        self.kill_confirmation = None;
        self.modal = Modal::None;
        self.kill_status = Some("kill cancelled".to_owned());
    }

    fn execute_kill_confirmation(&mut self) {
        self.execute_kill_confirmation_with(
            collector::collect_ports,
            platform::collect_process_context,
            process::prepare_termination,
            process::terminate_handle,
        );
    }

    fn execute_kill_confirmation_with<CollectPorts, CollectContext, Prepare, Terminate, Handle>(
        &mut self,
        mut collect_ports: CollectPorts,
        mut collect_context: CollectContext,
        mut prepare: Prepare,
        mut terminate: Terminate,
    ) where
        CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
        CollectContext: FnMut(u32) -> ProcessContext,
        Prepare: FnMut(u32) -> Result<Handle, TerminationOutcome>,
        Terminate: FnMut(&Handle, KillMode) -> TerminationOutcome,
    {
        let Some(confirmation) = self.kill_confirmation.take() else {
            return;
        };
        self.modal = Modal::None;

        let handle = match prepare(confirmation.target.pid) {
            Ok(handle) => handle,
            Err(outcome) => {
                self.kill_status = Some(termination_status_line(
                    &confirmation.target,
                    confirmation.mode,
                    &outcome,
                ));
                // A target that exited before we could open its pidfd is gone for
                // good, so re-collect to drop its freed row from the table. The
                // refresh is best-effort: the status reports only that the target
                // already exited, and the table (or the standard error line on a
                // failed re-collect) speaks for the snapshot rather than the status
                // claiming a refresh that may not have happened. Other prepare
                // failures leave the process running, so there's nothing to drop.
                if matches!(outcome, TerminationOutcome::AlreadyExited) {
                    self.finish_refresh_attempt(collect_ports(), Instant::now());
                }
                return;
            }
        };

        let mut fresh_rows = match collect_ports() {
            Ok(rows) => rows,
            Err(error) => {
                self.latest_error = Some(error.to_string());
                self.kill_status = Some(format!(
                    "collecting ports before kill failed; no termination was sent: {error}",
                ));
                return;
            }
        };
        mark_protected(&mut fresh_rows, &self.protected_processes);
        let fresh_context = collect_context(confirmation.target.pid);
        let target = match process::revalidate_confirmed_target(
            &confirmation.target,
            &fresh_rows,
            Some(&fresh_context),
        ) {
            Ok(target) => target,
            Err(outcome) => {
                self.kill_status = Some(termination_status_line(
                    &confirmation.target,
                    confirmation.mode,
                    &outcome,
                ));
                self.apply_successful_snapshot(fresh_rows, Instant::now());
                return;
            }
        };

        let outcome = terminate(&handle, confirmation.mode);
        self.kill_status = Some(termination_status_line(
            &target,
            confirmation.mode,
            &outcome,
        ));
        // Best-effort post-kill refresh so the freed port drops from the table.
        // The status reports only the signal result; a failed re-collect shows up
        // as the standard error line rather than letting the status overclaim a
        // refresh that did not run.
        self.finish_refresh_attempt(collect_ports(), Instant::now());
    }

    fn apply_successful_snapshot(&mut self, mut rows: Vec<PortEntry>, now: Instant) {
        // Installing a snapshot here makes it the authoritative view. If an older
        // worker is still running, keep its receiver installed so `refresh` cannot
        // start another scan, but discard that stale result when it eventually
        // lands. `poll_refresh` clears the worker before applying fresh results.
        if let Some(worker) = self.refresh_worker.as_mut() {
            worker.stale = true;
        }
        mark_protected(&mut rows, &self.protected_processes);
        self.all_rows = rows;
        self.last_successful_refresh = Some(now);
        self.latest_error = None;
        self.selected_context_key = None;
        self.selected_process_context = None;
        self.rebuild_visible_rows();
        if self.modal == Modal::Details {
            self.load_selected_process_context();
        }
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

    fn load_selected_process_context(&mut self) {
        let selected_key = self.selected_row().map(RowKey::from);
        if self.selected_context_key == selected_key {
            return;
        }

        self.selected_context_key = selected_key;
        self.selected_process_context = self
            .selected_row()
            .and_then(|entry| entry.pid)
            .map(platform::collect_process_context);
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

fn termination_status_line(
    target: &KillTarget,
    mode: KillMode,
    outcome: &TerminationOutcome,
) -> String {
    let delivery = mode.delivery_label(target.platform);
    match outcome {
        TerminationOutcome::Success => {
            format!("sent {delivery} to {}", target.identity())
        }
        TerminationOutcome::PermissionDenied => format!(
            "permission denied sending {delivery} to {}; {}",
            target.identity(),
            process::permission_denied_hint(target.platform),
        ),
        TerminationOutcome::OwnershipUnavailable => format!(
            "ownership for {} became unavailable before {delivery}; no termination was sent",
            target.identity(),
        ),
        TerminationOutcome::AlreadyExited => {
            format!(
                "{} already exited before termination was sent",
                target.identity()
            )
        }
        TerminationOutcome::Cancelled => "kill cancelled".to_owned(),
        TerminationOutcome::ProtectedProcess => format!(
            "{} is protected and requires stronger confirmation",
            target.identity(),
        ),
        TerminationOutcome::TargetChanged => format!(
            "{} no longer owns the confirmed port target; no termination was sent",
            target.identity(),
        ),
        TerminationOutcome::UnsafePid(reason) => {
            format!("unsafe PID blocked: {}", reason.message())
        }
        TerminationOutcome::UnknownFailure(error) => format!(
            "sending {delivery} to {} failed: {error}",
            target.identity(),
        ),
    }
}

pub(crate) fn kill_command_text(target: &KillTarget, mode: KillMode) -> String {
    command::render_kill_command(target.platform, target.pid, mode)
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
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::{App, Modal, RefreshWorker};
    use crate::config::Config;
    use crate::input::Action;
    use crate::model::{
        PermissionStatus, Platform, PortEntry, ProcessContext, Protocol, SocketState, SortMode,
    };
    use crate::process::{ConfirmationRequirement, KillMode, TerminationOutcome};

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

    fn entry_without_pid(port: u16) -> PortEntry {
        let mut row = entry(port, Some("hidden"));
        row.pid = None;
        row.permission = PermissionStatus::Partial;
        row
    }

    fn entry_with_pid(port: u16, pid: Option<u32>, protocol: Protocol, name: &str) -> PortEntry {
        PortEntry {
            protocol,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid,
            process_name: Some(name.to_owned()),
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

    fn context(start_time_ticks: u64) -> ProcessContext {
        ProcessContext {
            process_start_time_marker: Some(start_time_ticks),
            ..ProcessContext::default()
        }
    }

    fn set_confirmation_start_time(app: &mut App, start_time_ticks: u64) {
        app.kill_confirmation
            .as_mut()
            .expect("confirmation must be open")
            .target
            .process_start_time_marker = Some(start_time_ticks);
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
        assert_eq!(app.selected_process_context(), None);

        app.apply_action(Action::MoveDown);
        assert_eq!(app.selected_index(), Some(1));
        assert_eq!(app.selected_process_context(), None);

        app.apply_action(Action::MoveDown);
        assert_eq!(app.selected_index(), Some(1));
        assert_eq!(app.selected_process_context(), None);
    }

    #[test]
    fn empty_rows_have_no_selection_and_no_details_modal() {
        let mut app = app_with_rows(Vec::new());

        assert_eq!(app.selected_index(), None);
        assert_eq!(app.selected_process_context(), None);
        app.apply_action(Action::MoveDown);
        app.apply_action(Action::OpenDetails);
        assert_eq!(app.modal(), Modal::None);
    }

    #[test]
    fn modal_and_quit_actions_update_state() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

        assert_eq!(app.selected_process_context(), None);
        app.apply_action(Action::OpenDetails);
        assert_eq!(app.modal(), Modal::Details);
        assert!(app.selected_process_context().is_some());

        app.apply_action(Action::CloseModal);
        assert_eq!(app.modal(), Modal::None);

        app.apply_action(Action::OpenHelp);
        assert_eq!(app.modal(), Modal::Help);

        app.apply_action(Action::Quit);
        assert!(app.should_quit());
    }

    #[test]
    fn terminate_key_opens_normal_confirmation_for_selected_pid() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

        app.apply_action(Action::RequestTerminate);

        let confirmation = app
            .kill_confirmation()
            .expect("termination request opens confirmation");
        assert_eq!(app.modal(), Modal::ConfirmKill);
        assert_eq!(confirmation.target.pid, 3000);
        assert_eq!(confirmation.mode, KillMode::Terminate);
        assert_eq!(confirmation.requirement, ConfirmationRequirement::Yes);
    }

    #[test]
    fn confirmation_lists_all_ports_owned_by_selected_pid_from_full_snapshot() {
        let mut app = app_with_rows(vec![
            entry_with_pid(3000, Some(18422), Protocol::Tcp, "node"),
            entry_with_pid(5173, Some(18422), Protocol::Udp, "node"),
            entry_with_pid(8000, Some(18001), Protocol::Tcp, "cursor-agent"),
        ]);
        app.apply_action(Action::StartSearch);
        app.apply_action(Action::SearchAppend('3'));
        app.apply_action(Action::SearchAppend('0'));
        assert_eq!(app.rows().len(), 1);

        app.apply_action(Action::RequestTerminate);

        let confirmation = app
            .kill_confirmation()
            .expect("termination request opens confirmation");
        assert_eq!(confirmation.target.pid, 18422);
        assert_eq!(confirmation.target.ports.len(), 2);
        assert!(
            confirmation
                .target
                .ports_text()
                .contains("TCP 127.0.0.1:3000")
        );
        assert!(
            confirmation
                .target
                .ports_text()
                .contains("UDP 127.0.0.1:5173")
        );
    }

    #[test]
    fn force_key_uses_force_word_confirmation() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

        app.apply_action(Action::RequestForceKill);

        let confirmation = app
            .kill_confirmation()
            .expect("force request opens confirmation");
        assert_eq!(app.modal(), Modal::ConfirmKill);
        assert_eq!(confirmation.mode, KillMode::Force);
        assert_eq!(confirmation.requirement, ConfirmationRequirement::ForceWord);
    }

    #[test]
    fn windows_terminate_key_uses_yes_confirmation() {
        let mut row = entry(3000, Some("node.exe"));
        row.platform = Platform::Windows;
        let mut app = app_with_rows(vec![row]);

        app.apply_action(Action::RequestTerminate);

        let confirmation = app
            .kill_confirmation()
            .expect("windows termination request opens confirmation");
        assert_eq!(confirmation.mode, KillMode::Terminate);
        assert_eq!(confirmation.requirement, ConfirmationRequirement::Yes);
    }

    #[test]
    fn protected_process_uses_stronger_confirmation() {
        let mut app = app_with_rows(vec![entry(5432, Some("postgres"))]);

        app.apply_action(Action::RequestTerminate);

        let confirmation = app
            .kill_confirmation()
            .expect("protected target still opens confirmation");
        assert!(confirmation.target.protected);
        assert_eq!(
            confirmation.requirement,
            ConfirmationRequirement::ProtectedProcess,
        );
    }

    #[test]
    fn missing_pid_selection_reports_status_without_confirmation() {
        let mut app = app_with_rows(vec![entry_without_pid(8080)]);

        app.apply_action(Action::RequestTerminate);

        assert_eq!(app.modal(), Modal::None);
        assert!(app.kill_confirmation().is_none());
        assert_eq!(
            app.kill_status(),
            Some("selected row has no PID; cannot terminate"),
        );
    }

    #[test]
    fn kill_confirmation_can_be_cancelled() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTerminate);

        app.apply_action(Action::CancelKill);

        assert_eq!(app.modal(), Modal::None);
        assert!(app.kill_confirmation().is_none());
        assert_eq!(app.kill_status(), Some("kill cancelled"));
    }

    #[test]
    fn force_confirmation_input_is_bounded_and_editable() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestForceKill);

        app.apply_action(Action::KillInputAppend('f'));
        app.apply_action(Action::KillInputAppend('o'));
        app.apply_action(Action::KillInputBackspace);

        let confirmation = app
            .kill_confirmation()
            .expect("confirmation remains open while editing");
        assert_eq!(confirmation.input, "f");
        assert_eq!(confirmation.error, None);
    }

    #[test]
    fn auto_refresh_pauses_while_kill_confirmation_is_open() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTerminate);

        assert!(!app.refresh_due_at(
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(1),
        ));
        assert_eq!(
            app.time_until_refresh_at(
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(1),
            ),
            Duration::from_secs(1),
        );
    }

    #[test]
    fn confirmed_kill_revalidates_signals_and_refreshes_rows() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTerminate);
        set_confirmation_start_time(&mut app, 55);
        let fresh_before_signal = vec![entry(3000, Some("node"))];
        let fresh_after_signal = Vec::new();
        let mut collect_calls = 0;
        let mut terminated = None;

        app.execute_kill_confirmation_with(
            || {
                collect_calls += 1;
                if collect_calls == 1 {
                    Ok(fresh_before_signal.clone())
                } else {
                    Ok(fresh_after_signal.clone())
                }
            },
            |_| context(55),
            Ok::<u32, TerminationOutcome>,
            |pid, mode| {
                terminated = Some((*pid, mode));
                TerminationOutcome::Success
            },
        );

        assert_eq!(terminated, Some((3000, KillMode::Terminate)));
        assert_eq!(collect_calls, 2);
        assert_eq!(app.rows().len(), 0);
        assert_eq!(app.modal(), Modal::None);
        assert!(
            app.kill_status()
                .is_some_and(|status| status.contains("sent SIGTERM")),
        );
    }

    #[test]
    fn confirmed_kill_refuses_stale_process_identity_without_signalling() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTerminate);
        set_confirmation_start_time(&mut app, 55);
        let fresh_rows = vec![entry(3000, Some("node"))];
        let mut terminated = false;

        app.execute_kill_confirmation_with(
            || Ok(fresh_rows.clone()),
            |_| context(99),
            Ok::<u32, TerminationOutcome>,
            |_pid, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert!(!terminated);
        assert_eq!(app.rows().len(), 1);
        assert!(
            app.kill_status()
                .is_some_and(|status| status.contains("no longer owns")),
        );
    }

    #[test]
    fn prepare_already_exited_refreshes_snapshot_so_freed_port_drops() {
        // The target exits between confirmation and pidfd_open, so prepare reports
        // AlreadyExited before any signal is attempted. The status only says the
        // target already exited; the best-effort re-collect is what drops the freed
        // row, so verify that re-collect actually runs.
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        app.apply_action(Action::RequestTerminate);
        let fresh_after_exit: Vec<PortEntry> = Vec::new();
        let mut collect_calls = 0;
        let mut terminated = false;

        app.execute_kill_confirmation_with(
            || {
                collect_calls += 1;
                Ok(fresh_after_exit.clone())
            },
            |_| context(55),
            |_pid| -> Result<u32, TerminationOutcome> { Err(TerminationOutcome::AlreadyExited) },
            |_handle: &u32, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        // Prepare failed, so no signal was ever attempted...
        assert!(!terminated);
        // ...but the best-effort post-kill refresh still ran once and dropped the
        // freed port from the table.
        assert_eq!(collect_calls, 1);
        assert_eq!(app.rows().len(), 0);
        assert_eq!(app.modal(), Modal::None);
        assert!(
            app.kill_status()
                .is_some_and(|status| status.contains("already exited")),
        );
    }

    #[test]
    fn confirmed_kill_discards_stale_in_flight_refresh_so_freed_port_cannot_reappear() {
        // A background refresh spawned before the kill carries a pre-kill snapshot
        // (port 3000 still listening). Once the kill's own synchronous refresh
        // shows the port gone, that stale worker result must not be applied later
        // and resurrect the freed port. Keeping the in-flight receiver installed
        // also prevents a manual refresh from starting another worker before the
        // stale one drains.
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

        let (stale_sender, stale_receiver) = mpsc::channel();
        app.refresh_worker = Some(RefreshWorker {
            receiver: stale_receiver,
            stale: false,
        });

        app.apply_action(Action::RequestTerminate);
        set_confirmation_start_time(&mut app, 55);
        let fresh_before_signal = vec![entry(3000, Some("node"))];
        let fresh_after_signal: Vec<PortEntry> = Vec::new();
        let mut collect_calls = 0;

        app.execute_kill_confirmation_with(
            || {
                collect_calls += 1;
                if collect_calls == 1 {
                    Ok(fresh_before_signal.clone())
                } else {
                    Ok(fresh_after_signal.clone())
                }
            },
            |_| context(55),
            Ok::<u32, TerminationOutcome>,
            |_pid, _mode| TerminationOutcome::Success,
        );

        // The kill went through and the freed port is gone.
        assert_eq!(app.rows().len(), 0);
        // The pre-kill worker is still the only active worker; a manual refresh
        // must not replace its receiver before it drains.
        assert!(app.refresh_in_progress());
        app.apply_action(Action::Refresh);
        stale_sender
            .send(Ok(vec![entry(3000, Some("node"))]))
            .expect("stale worker receiver must stay installed");

        app.poll_refresh();
        assert!(!app.refresh_in_progress());
        assert!(app.rows().iter().all(|row| row.local_port != 3000));
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
    fn refresh_reloads_details_context_when_modal_stays_open() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

        app.apply_action(Action::OpenDetails);
        assert!(app.selected_process_context().is_some());

        app.apply_successful_snapshot(vec![entry(3000, Some("node"))], Instant::now());

        assert_eq!(app.selected_row().map(|row| row.local_port), Some(3000));
        assert_eq!(app.modal(), Modal::Details);
        assert!(app.selected_process_context().is_some());
    }

    #[test]
    fn refresh_invalidates_details_context_when_modal_is_closed() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);

        app.apply_action(Action::OpenDetails);
        assert!(app.selected_process_context().is_some());
        app.apply_action(Action::CloseModal);

        app.apply_successful_snapshot(vec![entry(3000, Some("node"))], Instant::now());

        assert_eq!(app.selected_row().map(|row| row.local_port), Some(3000));
        assert_eq!(app.modal(), Modal::None);
        assert_eq!(app.selected_process_context(), None);
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
    fn refresh_due_waits_for_in_flight_background_refresh() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        let (_sender, receiver) = mpsc::channel();
        app.refresh_worker = Some(RefreshWorker {
            receiver,
            stale: false,
        });

        assert!(app.refresh_in_progress());
        assert!(!app.refresh_due_at(
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(1),
        ));
        assert_eq!(
            app.time_until_refresh_at(
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(1),
            ),
            Duration::from_secs(1),
        );
    }

    #[test]
    fn polling_finished_background_refresh_applies_snapshot() {
        let mut app = app_with_rows(vec![entry(3000, Some("node"))]);
        let (sender, receiver) = mpsc::channel();
        app.refresh_worker = Some(RefreshWorker {
            receiver,
            stale: false,
        });
        sender
            .send(Ok(vec![entry(5173, Some("vite"))]))
            .expect("test refresh result must send");

        app.poll_refresh();

        assert!(!app.refresh_in_progress());
        assert_eq!(app.rows().len(), 1);
        assert_eq!(app.rows()[0].local_port, 5173);
        assert_eq!(app.latest_error(), None);
    }

    #[test]
    fn protected_names_are_marked_from_config() {
        let app = app_with_rows(vec![entry(5432, Some("postgres"))]);

        assert!(app.rows()[0].protected);
    }
}
