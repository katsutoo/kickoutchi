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
    Quit,
    Noop,
}

/// Map a key event to an app action.
pub(crate) fn action_for_key(key: KeyEvent, modal: Modal) -> Action {
    if key.kind != KeyEventKind::Press {
        return Action::Noop;
    }

    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return Action::Quit;
    }

    match key.code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Esc if modal == Modal::None => Action::Quit,
        KeyCode::Esc => Action::CloseModal,
        KeyCode::Char('?') => Action::OpenHelp,
        _ if modal != Modal::None => Action::Noop,
        KeyCode::Char('j') | KeyCode::Down => Action::MoveDown,
        KeyCode::Char('k') | KeyCode::Up => Action::MoveUp,
        KeyCode::Enter => Action::OpenDetails,
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

    #[test]
    fn quit_keys_quit() {
        assert_eq!(
            action_for_key(key(KeyCode::Char('q')), Modal::None),
            Action::Quit
        );
        assert_eq!(action_for_key(key(KeyCode::Esc), Modal::None), Action::Quit);
        assert_eq!(
            action_for_key(
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                Modal::None
            ),
            Action::Quit
        );
    }

    #[test]
    fn navigation_keys_move_when_no_modal_is_open() {
        assert_eq!(
            action_for_key(key(KeyCode::Char('j')), Modal::None),
            Action::MoveDown
        );
        assert_eq!(
            action_for_key(key(KeyCode::Down), Modal::None),
            Action::MoveDown
        );
        assert_eq!(
            action_for_key(key(KeyCode::Char('k')), Modal::None),
            Action::MoveUp
        );
        assert_eq!(
            action_for_key(key(KeyCode::Up), Modal::None),
            Action::MoveUp
        );
    }

    #[test]
    fn modal_keys_are_contextual() {
        assert_eq!(
            action_for_key(key(KeyCode::Enter), Modal::None),
            Action::OpenDetails
        );
        assert_eq!(
            action_for_key(key(KeyCode::Char('?')), Modal::None),
            Action::OpenHelp
        );
        assert_eq!(
            action_for_key(key(KeyCode::Esc), Modal::Help),
            Action::CloseModal
        );
        assert_eq!(
            action_for_key(key(KeyCode::Down), Modal::Help),
            Action::Noop
        );
        assert_eq!(
            action_for_key(key(KeyCode::Char('q')), Modal::Help),
            Action::Quit
        );
    }

    #[test]
    fn only_key_press_events_act() {
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert_eq!(action_for_key(release, Modal::None), Action::Noop);
    }
}
