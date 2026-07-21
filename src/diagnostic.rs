//! Strict "hey, this command line mentions your port" diagnostics.
//!
//! These are evidence, nothing more. They can point out that some command line
//! references the port you asked about, but they must never invent a table row
//! or claim ownership of a socket the OS didn't actually confirm. Hints, not
//! accusations.

use crate::display::{REPLACEMENT, is_default_ignorable, sanitize};
use crate::model::RelatedProcessHint;

const DIAGNOSTIC_COMMAND_DISPLAY_MAX_CHARS: usize = 240;

/// Pull a single, unambiguous port to diagnose out of the CLI list filters.
pub(crate) fn requested_diagnostic_port(port_arg: Option<u16>, filter_text: &str) -> Option<u16> {
    if port_arg.is_some() {
        return port_arg;
    }

    let mut requested = None;
    for token in filter_text.split_whitespace() {
        let parsed = token
            .strip_prefix("port:")
            .map(str::parse::<u16>)
            .or_else(|| Some(token.parse::<u16>()))
            .and_then(Result::ok);

        let Some(port) = parsed else {
            continue;
        };
        if requested.is_some_and(|existing| existing != port) {
            return None;
        }
        requested = Some(port);
    }
    requested
}

/// True when a command line carries strict, port-shaped evidence — not just a
/// number that happens to look like the port.
pub(crate) fn command_mentions_port(command_line: &str, port: u16) -> bool {
    let port_text = port.to_string();
    let tokens: Vec<&str> = command_line.split_whitespace().collect();

    for (index, token) in tokens.iter().enumerate() {
        if socket_token_mentions_port(token, &port_text)
            || assignment_mentions_port(token, &port_text)
            || flag_assignment_mentions_port(token, &port_text)
        {
            return true;
        }

        if is_port_flag(token)
            && tokens
                .get(index + 1)
                .is_some_and(|value| exact_port_value(value, &port_text))
        {
            return true;
        }

        if is_port_positional_command(token)
            && tokens
                .get(index + 1)
                .is_some_and(|value| exact_port_value(value, &port_text))
        {
            return true;
        }
    }

    false
}

pub(crate) fn diagnostic_message(port: u16, hints: &[RelatedProcessHint]) -> Option<String> {
    if hints.is_empty() {
        return None;
    }

    let mut message =
        format!("No confirmed listening TCP or bound UDP socket found on port {port}.\n");
    for hint in hints {
        // The name is attacker-controlled (a process names itself), and this
        // message lands on a human's terminal: sanitize it like every other
        // display surface. The command line takes the quoted-escape path in
        // `push_quoted_command` instead, so the name is the only raw field.
        let process = sanitize(hint.process_name.as_deref().unwrap_or("<unknown>"));
        message.push_str("Possible related process: PID ");
        message.push_str(&hint.pid.to_string());
        message.push_str(" (");
        message.push_str(&process);
        message.push_str(") command ");
        push_quoted_command(&mut message, &hint.command_line);
        message.push_str(" references this port, but no socket was confirmed.\n");
    }
    Some(message)
}

fn push_quoted_command(out: &mut String, command_line: &str) {
    out.push('"');
    for (index, ch) in command_line.chars().enumerate() {
        if index == DIAGNOSTIC_COMMAND_DISPLAY_MAX_CHARS {
            out.push_str("...");
            break;
        }
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            ch if ch.is_control() => out.push(' '),
            // `char::is_control` only covers the Cc controls; bidi overrides
            // and zero-width characters are category Cf and would pass raw,
            // letting a command line visually reorder this message. Same
            // policy as `sanitize`.
            ch if is_default_ignorable(ch) => out.push(REPLACEMENT),
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn is_port_flag(token: &str) -> bool {
    token == "--port" || token == "-p"
}

// Deliberately a singleton, not a general "command then bare number" rule.
// `python -m http.server 3000` is the one common case where the port is a bare
// positional argument with no flag. Generalizing to "any command followed by a
// number" would re-admit exactly the weak incidental matches (`--timeout 3000`,
// version numbers) the strict matcher exists to reject, so add entries here only
// for specific tools with the same bare-positional-port shape.
fn is_port_positional_command(token: &str) -> bool {
    token == "http.server"
}

fn flag_assignment_mentions_port(token: &str, port_text: &str) -> bool {
    let Some((flag, value)) = token.split_once('=') else {
        return false;
    };
    matches!(flag, "--port" | "-p") && exact_or_socket_port_value(value, port_text)
}

fn assignment_mentions_port(token: &str, port_text: &str) -> bool {
    let Some((name, value)) = token.split_once('=') else {
        return false;
    };
    let name_upper = name.to_ascii_uppercase();
    (name_upper == "PORT" || name_upper.ends_with("_PORT"))
        && exact_or_socket_port_value(value, port_text)
}

fn exact_or_socket_port_value(value: &str, port_text: &str) -> bool {
    exact_port_value(value, port_text) || socket_token_mentions_port(value, port_text)
}

fn exact_port_value(value: &str, port_text: &str) -> bool {
    value == port_text
}

fn socket_token_mentions_port(token: &str, port_text: &str) -> bool {
    let needle = format!(":{port_text}");
    let mut search_from = 0;
    while let Some(relative_index) = token[search_from..].find(&needle) {
        let index = search_from + relative_index;
        let after_index = index + needle.len();
        if token[after_index..]
            .chars()
            .next()
            .is_none_or(is_socket_port_terminator)
        {
            return true;
        }
        search_from = after_index;
    }
    false
}

fn is_socket_port_terminator(ch: char) -> bool {
    matches!(
        ch,
        '/' | '?' | '#' | ',' | ';' | ')' | ']' | '}' | '"' | '\''
    )
}

#[cfg(test)]
mod tests {
    use super::{command_mentions_port, diagnostic_message, requested_diagnostic_port};
    use crate::model::RelatedProcessHint;

    #[test]
    fn requested_port_requires_one_unambiguous_port() {
        assert_eq!(requested_diagnostic_port(Some(3000), ""), Some(3000));
        assert_eq!(requested_diagnostic_port(None, "port:3000"), Some(3000));
        assert_eq!(
            requested_diagnostic_port(None, "proto:tcp 3000"),
            Some(3000)
        );
        assert_eq!(requested_diagnostic_port(None, "3000 5173"), None);
        assert_eq!(requested_diagnostic_port(None, "node"), None);
    }

    #[test]
    fn command_matcher_accepts_strict_port_evidence() {
        assert!(command_mentions_port("python -m http.server :3000", 3000));
        assert!(command_mentions_port("vite --port 3000", 3000));
        assert!(command_mentions_port("vite --port=3000", 3000));
        assert!(command_mentions_port("server -p 3000", 3000));
        assert!(command_mentions_port("python3 -m http.server 3000", 3000));
        assert!(command_mentions_port("PORT=3000 node server.js", 3000));
        assert!(command_mentions_port("APP_PORT=127.0.0.1:3000 node", 3000));
        assert!(command_mentions_port("url=http://127.0.0.1:3000/", 3000));
    }

    #[test]
    fn command_matcher_rejects_weak_incidental_numbers() {
        assert!(!command_mentions_port("worker --timeout 3000", 3000));
        assert!(!command_mentions_port("tool --max-bytes 3000", 3000));
        assert!(!command_mentions_port("asset 3000k", 3000));
        assert!(!command_mentions_port("server --port 30000", 3000));
        assert!(!command_mentions_port("IMPORTANT=3000 node", 3000));
        assert!(!command_mentions_port("worker duration:3000ms", 3000));
        assert!(!command_mentions_port("worker host:3000abc", 3000));
    }

    #[test]
    fn diagnostic_message_sanitizes_hostile_process_names() {
        // A process can name itself with terminal escape bytes (comm is
        // attacker-controlled); the hint must reach the terminal with the
        // escape stripped, never raw.
        let hints = vec![RelatedProcessHint {
            pid: 12345,
            process_name: Some("evil\x1b[2Jname".to_owned()),
            command_line: "node --port 3000".to_owned(),
        }];

        let message = diagnostic_message(3000, &hints).expect("hint produces a message");

        assert!(!message.contains('\x1b'), "{message}");
        assert!(message.contains("evilname"), "{message}");
    }

    #[test]
    fn diagnostic_message_replaces_bidi_and_zero_width_in_command_lines() {
        // The command line is attacker-controlled too, and `char::is_control`
        // misses category-Cf characters: a U+202E override could visually
        // reorder the surrounding diagnostic text. The quoted path must apply
        // the same spoofing policy as `sanitize`.
        let hints = vec![RelatedProcessHint {
            pid: 12345,
            process_name: Some("node".to_owned()),
            command_line: "node \u{202e}--port 3000\u{200b}".to_owned(),
        }];

        let message = diagnostic_message(3000, &hints).expect("hint produces a message");

        assert!(!message.contains('\u{202e}'), "{message}");
        assert!(!message.contains('\u{200b}'), "{message}");
        assert!(message.contains("--port 3000"), "{message}");
    }

    #[test]
    fn diagnostic_message_is_evidence_not_ownership_claim() {
        let hints = vec![RelatedProcessHint {
            pid: 12345,
            process_name: Some("python3".to_owned()),
            command_line: "python3 -m http.server 3000".to_owned(),
        }];

        let message = diagnostic_message(3000, &hints).expect("hint produces a message");

        assert!(message.contains("No confirmed listening TCP or bound UDP socket"));
        assert!(message.contains("Possible related process"));
        assert!(message.contains("but no socket was confirmed"));
        assert!(!message.contains("owns this port"));
    }
}
