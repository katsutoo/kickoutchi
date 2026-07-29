//! Pure, bounded parser entry points for cargo-fuzz.
//!
//! This module exists only under `--cfg fuzzing`; it is absent from ordinary
//! library and release builds.

/// Exercise config decoding, TOML parsing, and semantic validation.
pub fn config(bytes: &[u8]) {
    crate::config::exercise_config_parser(bytes);
}

/// Exercise bounded Linux `/proc` stat, status, and socket-table parsing.
#[cfg(target_os = "linux")]
pub fn linux_proc(bytes: &[u8]) {
    crate::platform::linux::exercise_proc_parser(bytes);
}

/// Exercise release-archive member-path canonicalization.
pub fn archive_member_path(bytes: &[u8]) {
    const INPUT_BYTES_MAX: usize = 4 * 1024;
    let Some((&kind, raw)) = bytes.split_first() else {
        return;
    };
    if raw.len() > INPUT_BYTES_MAX {
        return;
    }
    let _ = crate::release_archive_path::safe_member_name(raw, kind == b'd');
}
