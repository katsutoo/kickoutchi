//! Runtime configuration: safe defaults, config-file loading, and CLI
//! overrides.
//!
//! Precedence, lowest to highest: built-in defaults, then the config file,
//! then CLI flags. The app must run with no config file at all; an *invalid*
//! file is a hard error that names the file and the bad value, because
//! silently falling back to defaults would hide the user's mistake.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::model::SortMode;

/// Bounds on the user-configurable refresh interval. Zero would busy-loop the
/// collector; anything above an hour is indistinguishable from "never" and
/// almost certainly a typo. Shared with the CLI flag parser so the file and
/// the flag enforce identical limits.
pub(crate) const REFRESH_INTERVAL_SECONDS_MIN: u64 = 1;
pub(crate) const REFRESH_INTERVAL_SECONDS_MAX: u64 = 3600;

/// Cap on the protected-process list. Matching is linear per row per refresh,
/// so the cap bounds that work; no real allowlist comes close to it, so
/// hitting it means a generated or corrupted config.
pub(crate) const PROTECTED_PROCESSES_MAX: usize = 256;

/// Why configuration loading failed.
#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    /// The file exists (or was explicitly requested) but could not be read.
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The file was read but its contents are not acceptable. `detail` names
    /// the offending key/value so the user can fix it without guessing.
    #[error("invalid config file {path}: {detail}")]
    Invalid { path: PathBuf, detail: String },
}

/// Resolved runtime settings. Every later feature reads this one shared
/// source instead of scattering literals across the code base.
#[derive(Debug)]
pub(crate) struct Config {
    /// Upper bound on how long the event loop waits for input before looping.
    ///
    /// This is a latency cap, not a busy-poll: queued input wakes the loop
    /// immediately, so the interval only bounds idle wait time. Internal
    /// tuning, deliberately not user-configurable.
    pub(crate) tick_interval: Duration,
    /// How often the TUI re-collects ports (auto-refresh lands in Phase 4).
    pub(crate) refresh_interval: Duration,
    /// Default table sort for the CLI and TUI.
    pub(crate) default_sort: SortMode,
    /// Hide conservative system/service rows from the default view.
    pub(crate) hide_system_processes: bool,
    /// Whether force kill prompts for confirmation when `--yes` is absent.
    pub(crate) confirm_force_kill: bool,
    /// Process names that require stronger confirmation before termination.
    pub(crate) protected_processes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_millis(250),
            refresh_interval: Duration::from_secs(3),
            default_sort: SortMode::Port,
            hide_system_processes: false,
            confirm_force_kill: true,
            // Defaults from PROJECT.md: things whose accidental death takes
            // down containers, databases, the init system, or a desktop.
            protected_processes: vec![
                "docker".to_owned(),
                "postgres".to_owned(),
                "systemd".to_owned(),
                "explorer.exe".to_owned(),
                "WindowServer".to_owned(),
            ],
        }
    }
}

/// On-disk shape of the config file. Every field is optional so a partial
/// file changes only what it names; most fields override their default, while
/// `protected_processes` extends it (see `merge_protected_processes`).
/// Unknown keys are rejected on purpose:
/// in a hand-edited file an unknown key is almost always a typo, and ignoring
/// it would make the user's setting silently do nothing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    refresh_interval_seconds: Option<u64>,
    default_sort: Option<SortMode>,
    hide_system_processes: Option<bool>,
    confirm_force_kill: Option<bool>,
    protected_processes: Option<Vec<String>>,
}

impl Config {
    /// Load configuration, resolving the file location.
    ///
    /// An explicit `path_override` (the `--config` flag) must exist: the user
    /// asked for that exact file, so a missing one is an error. The default
    /// platform path is the opposite — absent means "use defaults", which is
    /// the normal first-run state.
    pub(crate) fn load(path_override: Option<&Path>) -> Result<Self, ConfigError> {
        if let Some(path) = path_override {
            return Self::load_from(path);
        }
        let Some(path) = default_config_path() else {
            // No resolvable config directory on this system; nothing to read.
            return Ok(Self::default());
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text, &path),
            // Read-then-handle instead of an exists() pre-check: checking
            // first would race against file creation/removal for no benefit.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Read { path, source }),
        }
    }

    /// Load from an explicitly requested file. Any failure, including the
    /// file not existing, is an error here.
    fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text, path)
    }

    /// Parse and validate file contents. Split from the I/O so tests can
    /// exercise every validation rule without touching the filesystem.
    fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        let file: ConfigFile = toml::from_str(text).map_err(|error| ConfigError::Invalid {
            path: path.to_path_buf(),
            // toml's message already names the key, the line, and the
            // expected type, which satisfies "name the bad value".
            detail: error.to_string(),
        })?;

        let mut config = Self::default();

        if let Some(seconds) = file.refresh_interval_seconds {
            config.refresh_interval =
                validate_refresh_seconds(seconds).map_err(|detail| ConfigError::Invalid {
                    path: path.to_path_buf(),
                    detail,
                })?;
        }
        if let Some(sort) = file.default_sort {
            config.default_sort = sort;
        }
        if let Some(hide) = file.hide_system_processes {
            config.hide_system_processes = hide;
        }
        if let Some(confirm) = file.confirm_force_kill {
            config.confirm_force_kill = confirm;
        }
        if let Some(protected) = file.protected_processes {
            config.protected_processes =
                merge_protected_processes(config.protected_processes, protected).map_err(
                    |detail| ConfigError::Invalid {
                        path: path.to_path_buf(),
                        detail,
                    },
                )?;
        }

        Ok(config)
    }

    /// Apply CLI flag overrides, the highest-precedence layer.
    ///
    /// The value arrives pre-validated: clap enforces the same
    /// `REFRESH_INTERVAL_SECONDS_*` bounds at parse time, so a bad flag is a
    /// usage error (exit 2) before config is ever touched.
    pub(crate) fn apply_cli_overrides(&mut self, refresh_interval_seconds: Option<u64>) {
        if let Some(seconds) = refresh_interval_seconds {
            debug_assert!(
                validate_refresh_seconds(seconds).is_ok(),
                "clap must reject out-of-range refresh intervals before this point"
            );
            self.refresh_interval = Duration::from_secs(seconds);
        }
    }
}

/// Bounds-check a refresh interval from the config file.
fn validate_refresh_seconds(seconds: u64) -> Result<Duration, String> {
    if !(REFRESH_INTERVAL_SECONDS_MIN..=REFRESH_INTERVAL_SECONDS_MAX).contains(&seconds) {
        return Err(format!(
            "refresh_interval_seconds must be between {REFRESH_INTERVAL_SECONDS_MIN} and \
             {REFRESH_INTERVAL_SECONDS_MAX}, got {seconds}"
        ));
    }
    Ok(Duration::from_secs(seconds))
}

/// Validate the protected-process list: bounded in size, no empty names.
/// An empty name can never match a process, so it is always a mistake worth
/// surfacing rather than dead weight silently carried on every refresh.
fn validate_protected_processes(names: &[String]) -> Result<(), String> {
    if names.len() > PROTECTED_PROCESSES_MAX {
        return Err(format!(
            "protected_processes has {} entries, the maximum is {PROTECTED_PROCESSES_MAX}",
            names.len()
        ));
    }
    if names.iter().any(String::is_empty) {
        return Err("protected_processes must not contain empty names".to_owned());
    }
    Ok(())
}

/// Extend the built-in safety set with configured process names.
///
/// Config is additive by design: adding `redis` must not accidentally remove
/// protection from `systemd` or `postgres`. Exact de-duplication keeps the
/// bounded matching work stable without changing Unix case-sensitive semantics.
fn merge_protected_processes(
    mut defaults: Vec<String>,
    configured: Vec<String>,
) -> Result<Vec<String>, String> {
    for name in configured {
        if !defaults.iter().any(|existing| existing == &name) {
            defaults.push(name);
        }
    }
    validate_protected_processes(&defaults)?;
    Ok(defaults)
}

/// Platform default config file path (`~/.config/kickoutchi/config.toml` on
/// Linux via XDG). `None` when the OS exposes no config directory at all.
fn default_config_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("kickoutchi").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use super::{Config, ConfigError, PROTECTED_PROCESSES_MAX};
    use crate::model::SortMode;

    /// Tests go through `Config::parse` with a fixed fake path: the I/O layer
    /// above it is a thin read wrapper, while every rule worth pinning lives
    /// in parsing and validation.
    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse(text, Path::new("/tmp/kickoutchi-test/config.toml"))
    }

    fn invalid_detail(result: Result<Config, ConfigError>) -> String {
        match result {
            Err(ConfigError::Invalid { detail, .. }) => detail,
            other => panic!("expected ConfigError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn defaults_are_safe() {
        let config = Config::default();
        assert_eq!(config.refresh_interval, Duration::from_secs(3));
        assert_eq!(config.default_sort, SortMode::Port);
        assert!(!config.hide_system_processes);
        assert!(config.confirm_force_kill);
        assert!(config.protected_processes.contains(&"systemd".to_owned()));
    }

    #[test]
    fn empty_file_yields_defaults() {
        let config = parse("").expect("empty file is valid");
        assert_eq!(config.refresh_interval, Config::default().refresh_interval);
        assert_eq!(config.default_sort, Config::default().default_sort);
        assert_eq!(
            config.hide_system_processes,
            Config::default().hide_system_processes
        );
    }

    #[test]
    fn partial_file_overrides_only_named_values() {
        let config = parse("refresh_interval_seconds = 10").expect("valid");
        assert_eq!(config.refresh_interval, Duration::from_secs(10));
        // Everything else stays at its default.
        assert_eq!(config.default_sort, SortMode::Port);
        assert!(!config.hide_system_processes);
        assert!(config.confirm_force_kill);
    }

    #[test]
    fn full_file_parses() {
        let config = parse(
            r#"
            refresh_interval_seconds = 5
            default_sort = "scope"
            hide_system_processes = true
            confirm_force_kill = false
            protected_processes = ["redis", "postgres"]
            "#,
        )
        .expect("valid");
        assert_eq!(config.refresh_interval, Duration::from_secs(5));
        assert_eq!(config.default_sort, SortMode::Scope);
        assert!(config.hide_system_processes);
        assert!(!config.confirm_force_kill);
        assert!(config.protected_processes.contains(&"docker".to_owned()));
        assert!(config.protected_processes.contains(&"postgres".to_owned()));
        assert!(config.protected_processes.contains(&"systemd".to_owned()));
        assert!(config.protected_processes.contains(&"redis".to_owned()));
        assert_eq!(
            config
                .protected_processes
                .iter()
                .filter(|name| name.as_str() == "postgres")
                .count(),
            1
        );
    }

    #[test]
    fn broken_toml_is_an_invalid_config_error() {
        let detail = invalid_detail(parse("refresh_interval_seconds = "));
        assert!(!detail.is_empty());
    }

    #[test]
    fn unknown_key_is_rejected_and_named() {
        let detail = invalid_detail(parse("refresh_intreval_seconds = 3"));
        assert!(
            detail.contains("refresh_intreval_seconds"),
            "detail: {detail}"
        );
    }

    #[test]
    fn bad_sort_value_is_named() {
        let detail = invalid_detail(parse(r#"default_sort = "alphabetical""#));
        assert!(detail.contains("alphabetical"), "detail: {detail}");
    }

    #[test]
    fn zero_refresh_interval_is_rejected_with_the_value_named() {
        let detail = invalid_detail(parse("refresh_interval_seconds = 0"));
        assert!(
            detail.contains("refresh_interval_seconds"),
            "detail: {detail}"
        );
        assert!(detail.contains("got 0"), "detail: {detail}");
    }

    #[test]
    fn oversized_protected_list_is_rejected() {
        let names: Vec<String> = (0..=PROTECTED_PROCESSES_MAX)
            .map(|index| format!("\"process-{index}\""))
            .collect();
        let text = format!("protected_processes = [{}]", names.join(", "));
        let detail = invalid_detail(parse(&text));
        assert!(detail.contains("maximum"), "detail: {detail}");
    }

    #[test]
    fn empty_protected_name_is_rejected() {
        let detail = invalid_detail(parse(r#"protected_processes = ["docker", ""]"#));
        assert!(detail.contains("empty"), "detail: {detail}");
    }

    #[test]
    fn explicitly_requested_missing_file_is_an_error() {
        let result = Config::load(Some(Path::new(
            "/nonexistent/kickoutchi-test/never-here.toml",
        )));
        assert!(matches!(result, Err(ConfigError::Read { .. })));
    }

    #[test]
    fn cli_flag_overrides_file_value() {
        let mut config = parse("refresh_interval_seconds = 5").expect("valid");
        config.apply_cli_overrides(Some(9));
        assert_eq!(config.refresh_interval, Duration::from_secs(9));
        // No flag given: the file value stands.
        let mut config = parse("refresh_interval_seconds = 5").expect("valid");
        config.apply_cli_overrides(None);
        assert_eq!(config.refresh_interval, Duration::from_secs(5));
    }
}
