//! Human-facing display sanitizer.
//!
//! Process names, paths, and command lines are read straight from the OS and can
//! contain control characters, newlines, or ANSI escape sequences. The JSON path
//! keeps that data raw because scripts need the real values, but anything a human
//! sees — tables, details panels, kill confirmations — should pass through here
//! first so a funky process can't move the cursor, hide text, or fake a prompt.

const REPLACEMENT: char = '�';

/// Make an untrusted string safe to print where humans read it.
///
/// - Tabs become spaces so columns don't drift.
/// - Carriage returns and line feeds become spaces so a single row can't break
///   into multiple lines.
/// - Other ASCII control characters and the C0/C1 control ranges become the
///   replacement character.
/// - ANSI escape sequences are stripped so a process name can't redraw the
///   terminal or fake a confirmation prompt.
/// - Bidi and zero-width formatting characters become the replacement character,
///   so names cannot hide or reorder text in a terminal prompt.
/// - Everything else is preserved, including visible Unicode.
pub(crate) fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\t' || ch == '\n' || ch == '\r' {
            out.push(' ');
            continue;
        }

        // ANSI escape: ESC followed by '[' or '(' or ')' or '#' or any other
        // standard introducer, then parameter bytes and a final letter.
        if ch == '\x1b' {
            strip_ansi_sequence(&mut chars);
            continue;
        }

        if is_control(ch) || is_display_spoofing_format(ch) {
            out.push(REPLACEMENT);
            continue;
        }

        out.push(ch);
    }

    out
}

/// Drop the rest of a single ANSI escape sequence from the iterator.
///
/// This handles CSI (`ESC [` ... final byte), two-character sequences such as
/// `ESC (`, and OSC/PM/APC strings that end with BEL or ST. It is intentionally
/// conservative: it stops at the first byte that does not belong to the
/// sequence, so a malformed escape does not eat the whole string.
fn strip_ansi_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let Some(introducer) = chars.peek().copied() else {
        return;
    };

    // OSC (ESC ]), PM (ESC ^), APC (ESC _): consume until BEL or ST.
    if matches!(introducer, ']' | '^' | '_') {
        chars.next();
        loop {
            match chars.next() {
                Some('\x07') | None => break,
                Some('\x1b') => {
                    if chars.peek() == Some(&'\\') {
                        chars.next();
                    }
                    break;
                }
                _ => {}
            }
        }
        return;
    }

    // CSI: ESC [ parameter bytes (0x30-0x3F) then intermediate/final bytes
    // (0x20-0x7E). For all other introducers, consume parameter bytes the same
    // way; most non-CSI introducers have zero or one parameter byte.
    chars.next();
    loop {
        match chars.peek().copied() {
            Some(c) if ('\x30'..='\x3f').contains(&c) => {
                chars.next();
            }
            Some('\x20'..='\x7e') => {
                chars.next();
                break;
            }
            _ => break,
        }
    }
}

fn is_control(ch: char) -> bool {
    matches!(ch, '\x00'..='\x1f' | '\x7f' | '\u{0080}'..='\u{009f}')
}

fn is_display_spoofing_format(ch: char) -> bool {
    matches!(
        ch,
        // Arabic Letter Mark, zero-width marks/joiners, bidi isolates/overrides,
        // and byte-order/word joiners. They render invisibly or reorder text.
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}'
    )
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn leaves_clean_text_unchanged() {
        assert_eq!(sanitize("node server.js"), "node server.js");
        assert_eq!(sanitize("/usr/bin/node"), "/usr/bin/node");
    }

    #[test]
    fn replaces_newlines_and_tabs_with_space() {
        assert_eq!(sanitize("node\nserver\tjs"), "node server js");
        assert_eq!(sanitize("line1\r\nline2"), "line1  line2");
    }

    #[test]
    fn replaces_control_characters() {
        assert_eq!(sanitize("no\x00null"), "no�null");
        assert_eq!(sanitize("beep\x07"), "beep�");
    }

    #[test]
    fn strips_ansi_escape_sequences() {
        assert_eq!(sanitize("\x1b[31mred\x1b[0m"), "red");
        assert_eq!(sanitize("\x1b[1;31mbold red\x1b[m"), "bold red");
        assert_eq!(sanitize("\x1b]0;title\x07after"), "after");
    }

    #[test]
    fn preserves_unicode() {
        assert_eq!(sanitize("héllo 世界 🌍"), "héllo 世界 🌍");
    }

    #[test]
    fn replaces_bidi_and_zero_width_formatting() {
        assert_eq!(sanitize("safe\u{202e}txt"), "safe�txt");
        assert_eq!(sanitize("zero\u{200b}width"), "zero�width");
    }
}
