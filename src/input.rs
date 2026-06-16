//! Keyboard input mapping for the TUI.
//!
//! This module deliberately returns small actions instead of mutating `App`
//! directly. That keeps crossterm details out of the state machine and makes
//! the key contract easy to test without a terminal.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::Modal;

/// One state transition requested by a key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    MoveDown,
    MoveUp,
    OpenDetails,
    OpenHelp,
    CloseModal,
    RequestTerminate,
    RequestForceKill,
    SubmitKillConfirmation,
    KillInputAppend(char),
    KillInputBackspace,
    CancelKill,
    Refresh,
    StartSearch,
    SearchAppend(char),
    SearchBackspace,
    FinishSearch,
    CancelSearch,
    CycleSort,
    Quit,
    Noop,
}

/// Map a key event to an app action.
///
/// `filter_active` lets a single `Esc` outside search mode clear an applied
/// filter instead of quitting: a user who set a filter, pressed Enter to finish
/// editing, then reflexively hits Esc should lose the filter, not the whole
/// session. Esc only quits once there is no modal to close and no filter to
/// clear. Precedence is fixed: modal first, then filter, then quit.
pub(crate) fn action_for_key(
    key: KeyEvent,
    modal: Modal,
    search_mode: bool,
    filter_active: bool,
) -> Action {
    if key.kind != KeyEventKind::Press {
        return Action::Noop;
    }

    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return Action::Quit;
    }

    if modal == Modal::ConfirmKill {
        return kill_confirmation_action_for_key(key);
    }

    if search_mode {
        return search_action_for_key(key);
    }

    match key.code {
        KeyCode::Esc if modal != Modal::None => Action::CloseModal,
        KeyCode::Esc if filter_active => Action::CancelSearch,
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        KeyCode::Char('?') => Action::OpenHelp,
        _ if modal != Modal::None => Action::Noop,
        KeyCode::Char('r') => Action::Refresh,
        KeyCode::Char('/') => Action::StartSearch,
        KeyCode::Char('s') => Action::CycleSort,
        KeyCode::Char('x') => Action::RequestTerminate,
        KeyCode::Char('X') => Action::RequestForceKill,
        KeyCode::Char('j') | KeyCode::Down => Action::MoveDown,
        KeyCode::Char('k') | KeyCode::Up => Action::MoveUp,
        KeyCode::Enter => Action::OpenDetails,
        _ => Action::Noop,
    }
}

fn kill_confirmation_action_for_key(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc => Action::CancelKill,
        KeyCode::Enter => Action::SubmitKillConfirmation,
        KeyCode::Backspace => Action::KillInputBackspace,
        KeyCode::Char(ch)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            Action::KillInputAppend(ch)
        }
        _ => Action::Noop,
    }
}

fn search_action_for_key(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc => Action::CancelSearch,
        KeyCode::Enter => Action::FinishSearch,
        KeyCode::Backspace => Action::SearchBackspace,
        KeyCode::Char(ch)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            Action::SearchAppend(ch)
        }
        _ => Action::Noop,
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, action_for_key};
    use crate::app::Modal;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Most cases do not depend on an active filter; the Esc-clears-filter test
    /// below passes `filter_active` explicitly. Keeping the common case in one
    /// helper avoids two confusable trailing bools at every call site.
    fn act(code: KeyCode, modal: Modal, search_mode: bool) -> Action {
        action_for_key(key(code), modal, search_mode, false)
    }

    #[test]
    fn quit_keys_quit() {
        assert_eq!(act(KeyCode::Char('q'), Modal::None, false), Action::Quit);
        assert_eq!(act(KeyCode::Esc, Modal::None, false), Action::Quit);
        assert_eq!(
            action_for_key(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                Modal::None,
                false,
                false,
            ),
            Action::Quit
        );
    }

    #[test]
    fn navigation_keys_move_when_no_modal_is_open() {
        assert_eq!(
            act(KeyCode::Char('j'), Modal::None, false),
            Action::MoveDown
        );
        assert_eq!(act(KeyCode::Down, Modal::None, false), Action::MoveDown);
        assert_eq!(act(KeyCode::Char('k'), Modal::None, false), Action::MoveUp);
        assert_eq!(act(KeyCode::Up, Modal::None, false), Action::MoveUp);
    }

    #[test]
    fn modal_keys_are_contextual() {
        assert_eq!(act(KeyCode::Enter, Modal::None, false), Action::OpenDetails);
        assert_eq!(
            act(KeyCode::Char('?'), Modal::None, false),
            Action::OpenHelp
        );
        assert_eq!(act(KeyCode::Esc, Modal::Help, false), Action::CloseModal);
        assert_eq!(act(KeyCode::Down, Modal::Help, false), Action::Noop);
        assert_eq!(act(KeyCode::Char('q'), Modal::Help, false), Action::Quit);
    }

    #[test]
    fn refresh_search_and_sort_keys_work_without_modal() {
        assert_eq!(act(KeyCode::Char('r'), Modal::None, false), Action::Refresh);
        assert_eq!(
            act(KeyCode::Char('/'), Modal::None, false),
            Action::StartSearch
        );
        assert_eq!(
            act(KeyCode::Char('s'), Modal::None, false),
            Action::CycleSort
        );
    }

    #[test]
    fn kill_keys_request_termination_without_modal() {
        assert_eq!(
            act(KeyCode::Char('x'), Modal::None, false),
            Action::RequestTerminate,
        );
        assert_eq!(
            act(KeyCode::Char('X'), Modal::None, false),
            Action::RequestForceKill,
        );
    }

    #[test]
    fn kill_confirmation_modal_captures_text_until_submit_or_cancel() {
        assert_eq!(
            act(KeyCode::Char('q'), Modal::ConfirmKill, false),
            Action::KillInputAppend('q'),
        );
        assert_eq!(
            act(KeyCode::Backspace, Modal::ConfirmKill, false),
            Action::KillInputBackspace,
        );
        assert_eq!(
            act(KeyCode::Enter, Modal::ConfirmKill, false),
            Action::SubmitKillConfirmation,
        );
        assert_eq!(
            act(KeyCode::Esc, Modal::ConfirmKill, false),
            Action::CancelKill,
        );
    }

    #[test]
    fn search_mode_treats_plain_keys_as_query_text() {
        assert_eq!(
            act(KeyCode::Char('q'), Modal::None, true),
            Action::SearchAppend('q')
        );
        assert_eq!(
            act(KeyCode::Backspace, Modal::None, true),
            Action::SearchBackspace
        );
        assert_eq!(act(KeyCode::Enter, Modal::None, true), Action::FinishSearch);
        assert_eq!(act(KeyCode::Esc, Modal::None, true), Action::CancelSearch);
    }

    #[test]
    fn esc_clears_an_applied_filter_before_quitting() {
        // Search editing is finished (search_mode false) but a filter is still
        // applied: Esc must clear the filter, not quit. A second Esc, with no
        // filter left, quits. An open modal still wins over both.
        assert_eq!(
            action_for_key(key(KeyCode::Esc), Modal::None, false, true),
            Action::CancelSearch
        );
        assert_eq!(
            action_for_key(key(KeyCode::Esc), Modal::None, false, false),
            Action::Quit
        );
        assert_eq!(
            action_for_key(key(KeyCode::Esc), Modal::Help, false, true),
            Action::CloseModal
        );
    }

    #[test]
    fn only_key_press_events_act() {
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert_eq!(
            action_for_key(release, Modal::None, false, false),
            Action::Noop
        );
    }
}
