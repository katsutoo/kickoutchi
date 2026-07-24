//! Runtime config: safe defaults, loading the config file, and CLI overrides.
//!
//! Precedence has layers — like onions, like ogres: built-in defaults at the
//! bottom, then the config file, then CLI flags on top. The app has to run fine
//! with no config file at all — but an *invalid* one is a hard error that names
//! the file and the bad value, because quietly falling back to defaults would
//! just hide the user's typo.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::de::{Error as _, IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use thiserror::Error;

use crate::labels::{LABEL_SELECTORS_MAX, LabelInput, LabelRegistry};
use crate::model::SortMode;
use crate::protection;

/// Limits on the refresh interval. Zero would just busy-loop the collector, and
/// anything past an hour is basically "never" and almost certainly a typo. The
/// CLI flag parser shares these, so the file and the flag agree on the limits.
pub(crate) const REFRESH_INTERVAL_SECONDS_MIN: u64 = 1;
pub(crate) const REFRESH_INTERVAL_SECONDS_MAX: u64 = 3600;

/// Cap on the protected-process list. Matching is linear per row per refresh, so
/// this keeps that work bounded. No real allowlist gets anywhere near it — if you
/// hit this, the config was generated or corrupted.
pub(crate) const PROTECTED_PROCESSES_MAX: usize = 256;

/// Config is hand-written and tiny in normal use. This cap prevents files,
/// pipes, and special devices from driving unbounded allocation or reads.
pub(crate) const CONFIG_FILE_MAX_BYTES: usize = 64 * 1024;

/// What went wrong while loading config.
#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    /// The file's there (or was explicitly asked for) but we couldn't read it.
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// We read the file, but its contents don't fly. `detail` calls out the
    /// offending key/value so the user can fix it without guessing.
    #[error("invalid config file {path}: {detail}")]
    Invalid { path: PathBuf, detail: String },
}

/// The resolved runtime settings. Everything downstream reads this one shared
/// source instead of sprinkling magic literals all over the codebase.
#[derive(Debug)]
pub(crate) struct Config {
    /// The longest the event loop will sit waiting for input before looping.
    ///
    /// It's a latency cap, not a busy-poll: queued input wakes the loop right
    /// away, so this only bounds how long we idle. Internal knob — not something
    /// we hand to users.
    pub(crate) tick_interval: Duration,
    /// How often the TUI re-collects ports for auto-refresh.
    pub(crate) refresh_interval: Duration,
    /// Default table sort for the CLI and TUI.
    pub(crate) default_sort: SortMode,
    /// Hide conservative system/service rows from the default view.
    pub(crate) hide_system_processes: bool,
    /// Whether force kill uses the stronger typed confirmation when `--yes` is absent.
    pub(crate) confirm_force_kill: bool,
    /// Process names that require stronger confirmation before termination.
    pub(crate) protected_processes: Vec<String>,
    /// Validated endpoint annotations shared by CLI, TUI, and future diagnostics.
    pub(crate) labels: LabelRegistry,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_millis(250),
            refresh_interval: Duration::from_secs(3),
            default_sort: SortMode::Port,
            hide_system_processes: false,
            confirm_force_kill: true,
            // Built-in safety defaults: the stuff whose accidental death takes
            // your containers, database, init system, or desktop down with it.
            protected_processes: protection::default_protected_processes(),
            labels: LabelRegistry::default(),
        }
    }
}

/// The on-disk shape of the config file. Every field is optional, so a partial
/// file only changes what it actually names; most fields override their default,
/// while `protected_processes` extends it (see `merge_protected_processes`).
/// Unknown keys are rejected on purpose: in a hand-edited file an unknown key is
/// almost always a typo, and ignoring it would make the user's setting silently
/// do nothing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    refresh_interval_seconds: Option<u64>,
    default_sort: Option<SortMode>,
    hide_system_processes: Option<bool>,
    confirm_force_kill: Option<bool>,
    protected_processes: Option<Vec<String>>,
    ports: Option<PortLabels>,
}

#[derive(Debug)]
struct PortLabels(Vec<PortLabelFile>);

impl<'de> Deserialize<'de> for PortLabels {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(PortLabelsVisitor)
    }
}

struct PortLabelsVisitor;

impl<'de> Visitor<'de> for PortLabelsVisitor {
    type Value = PortLabels;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an array of endpoint label selectors")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut ports = Vec::new();
        loop {
            let index = ports.len();
            if index == LABEL_SELECTORS_MAX {
                return match sequence.next_element::<IgnoredAny>() {
                    Ok(Some(_)) => Err(A::Error::custom(format!(
                        "ports has more than {LABEL_SELECTORS_MAX} selectors"
                    ))),
                    Ok(None) => Ok(PortLabels(ports)),
                    Err(error) => Err(A::Error::custom(format!("ports[{index}]: {error}"))),
                };
            }
            match sequence.next_element::<PortLabelFile>() {
                Ok(Some(port)) => ports.push(port),
                Ok(None) => return Ok(PortLabels(ports)),
                Err(error) => {
                    return Err(A::Error::custom(format!("ports[{index}]: {error}")));
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortLabelFile {
    protocol: String,
    address: String,
    port: u64,
    scope_id: Option<u64>,
    label: String,
}

impl Config {
    /// Load config, figuring out which file to read.
    ///
    /// An explicit `path_override` (the `--config` flag) has to exist: the user
    /// pointed at that exact file, so a missing one is an error. The default
    /// platform path is the opposite — not being there just means "use defaults",
    /// which is the totally normal first-run state.
    pub(crate) fn load(path_override: Option<&Path>) -> Result<Self, ConfigError> {
        if let Some(path) = path_override {
            return Self::load_from(path);
        }
        Self::load_default(default_config_path())
    }

    fn load_default(path: Option<PathBuf>) -> Result<Self, ConfigError> {
        let Some(path) = path else {
            // No config directory on this system, so there's nothing to read.
            return Ok(Self::default());
        };
        match read_config_file(&path) {
            Ok(text) => Self::parse(&text, &path),
            // We just try the read and handle the result instead of checking
            // exists() first — that check would only race file creation/removal
            // for no real benefit.
            Err(ConfigError::Read { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(Self::default())
            }
            Err(error) => Err(error),
        }
    }

    /// Load from a file the user explicitly asked for. Any failure here — the
    /// file not existing included — is an error.
    fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let text = read_config_file(path)?;
        Self::parse(&text, path)
    }

    /// Parse and validate the file contents. Kept separate from the I/O so tests
    /// can hammer every validation rule without touching the filesystem.
    fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        let file: ConfigFile = toml::from_str(text).map_err(|error| ConfigError::Invalid {
            path: path.to_path_buf(),
            // toml's own message already names the key, the line, and the
            // expected type — exactly the "name the bad value" we're after.
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
        if let Some(PortLabels(ports)) = file.ports {
            let inputs = ports
                .into_iter()
                .map(|port| LabelInput {
                    protocol: port.protocol,
                    address: port.address,
                    port: port.port,
                    scope_id: port.scope_id,
                    label: port.label,
                })
                .collect();
            config.labels =
                LabelRegistry::from_inputs(inputs).map_err(|error| ConfigError::Invalid {
                    path: path.to_path_buf(),
                    detail: error.to_string(),
                })?;
        }

        Ok(config)
    }

    /// Apply CLI flag overrides — the top of the precedence stack.
    ///
    /// The value's already validated by the time it lands here: clap enforces the
    /// same `REFRESH_INTERVAL_SECONDS_*` bounds at parse time, so a bad flag is a
    /// usage error (exit 2) long before config gets involved.
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

fn read_config_file(path: &Path) -> Result<String, ConfigError> {
    let file = std::fs::File::open(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    read_config_from(file, path)
}

fn read_config_from(mut reader: impl Read, path: &Path) -> Result<String, ConfigError> {
    let limit = u64::try_from(CONFIG_FILE_MAX_BYTES).expect("config byte limit must fit in u64");
    let mut bytes = Vec::with_capacity(CONFIG_FILE_MAX_BYTES);
    reader
        .by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    let mut sentinel = [0_u8; 1];
    let has_excess = reader
        .read(&mut sentinel)
        .map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?
        != 0;
    if has_excess {
        return Err(ConfigError::Invalid {
            path: path.to_path_buf(),
            detail: format!("file exceeds the {CONFIG_FILE_MAX_BYTES}-byte limit"),
        });
    }
    String::from_utf8(bytes).map_err(|error| ConfigError::Invalid {
        path: path.to_path_buf(),
        detail: format!("file is not valid UTF-8: {error}"),
    })
}

/// Make sure a refresh interval from the config file is actually in range.
fn validate_refresh_seconds(seconds: u64) -> Result<Duration, String> {
    if !(REFRESH_INTERVAL_SECONDS_MIN..=REFRESH_INTERVAL_SECONDS_MAX).contains(&seconds) {
        return Err(format!(
            "refresh_interval_seconds must be between {REFRESH_INTERVAL_SECONDS_MIN} and \
             {REFRESH_INTERVAL_SECONDS_MAX}, got {seconds}"
        ));
    }
    Ok(Duration::from_secs(seconds))
}

/// Sanity-check the protected-process list: bounded in size, no empty names.
/// An empty name can never match anything, so it's always a mistake worth
/// flagging rather than dead weight we'd haul around on every refresh.
///
/// The size bound applies to the merged list, but the user only sees their
/// own file: the message spells out the built-in share of the count so "273
/// entries" is not a mystery to someone who wrote 250.
fn validate_protected_processes(names: &[String], default_count: usize) -> Result<(), String> {
    if names.len() > PROTECTED_PROCESSES_MAX {
        return Err(format!(
            "protected_processes has {} entries ({} configured plus {default_count} built-in \
             defaults), the maximum is {PROTECTED_PROCESSES_MAX}",
            names.len(),
            names.len() - default_count,
        ));
    }
    if names.iter().any(String::is_empty) {
        return Err("protected_processes must not contain empty names".to_owned());
    }
    Ok(())
}

/// Add the user's configured names on top of the built-in safety set.
///
/// Config is additive on purpose: adding `redis` must not quietly strip
/// protection from `systemd` or `postgres`. Exact de-duplication keeps the
/// bounded matching work steady without messing with Unix case-sensitivity.
fn merge_protected_processes(
    mut defaults: Vec<String>,
    configured: Vec<String>,
) -> Result<Vec<String>, String> {
    let default_count = defaults.len();
    for name in configured {
        if !defaults.iter().any(|existing| existing == &name) {
            defaults.push(name);
        }
    }
    validate_protected_processes(&defaults, default_count)?;
    Ok(defaults)
}

/// The platform's default config path (`~/.config/kickoutchi/config.toml` on
/// Linux via XDG). `None` if the OS hands us no config directory at all.
fn default_config_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("kickoutchi").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::fs;
    use std::io::{self, Read};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;
    use std::time::Duration;

    use super::{
        CONFIG_FILE_MAX_BYTES, Config, ConfigError, LABEL_SELECTORS_MAX, PROTECTED_PROCESSES_MAX,
        read_config_from,
    };
    use crate::model::Protocol;
    use crate::model::SortMode;

    /// Tests go through `Config::parse` with a fixed fake path: the I/O above it
    /// is a thin read wrapper, and every rule worth pinning lives down here in
    /// parsing and validation.
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
    fn endpoint_labels_parse_and_resolve_exact_before_wildcard() {
        let config = parse(
            r#"
[[ports]]
protocol = "tcp"
address = "*"
port = 3000
label = "development"

[[ports]]
protocol = "tcp"
address = "127.0.0.1"
port = 3000
label = "web dev"
"#,
        )
        .expect("valid endpoint labels parse");

        assert_eq!(
            config
                .labels
                .resolve_parts(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), 3000, None,),
            Some("web dev")
        );
        assert_eq!(
            config.labels.resolve_parts(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                3000,
                None,
            ),
            Some("development")
        );
    }

    #[test]
    fn endpoint_label_errors_name_the_index_without_reflecting_hostile_text() {
        let detail = invalid_detail(parse(
            r#"
[[ports]]
protocol = "tcp"
address = "*"
port = 3000
label = "evil\u001b[2J"
"#,
        ));

        assert!(detail.starts_with("ports[0].label"), "{detail}");
        assert!(!detail.contains("evil"), "{detail}");
        assert!(!detail.contains('\u{1b}'), "{detail}");
    }

    #[test]
    fn endpoint_label_selector_rejects_unknown_fields() {
        let detail = invalid_detail(parse(
            r#"
[[ports]]
protocol = "tcp"
address = "*"
port = 3000
label = "web"
hostname = "localhost"
"#,
        ));

        assert!(detail.contains("ports[0]"), "{detail}");
        assert!(detail.contains("unknown field `hostname`"), "{detail}");
    }

    #[test]
    fn endpoint_label_missing_field_names_the_selector_index() {
        let detail = invalid_detail(parse(
            r#"
[[ports]]
protocol = "tcp"
port = 3000
label = "web"
"#,
        ));

        assert!(detail.contains("ports[0]"), "{detail}");
        assert!(detail.contains("missing field `address`"), "{detail}");
    }

    #[test]
    fn endpoint_label_config_accepts_256_selectors_and_rejects_257th() {
        let mut text = String::new();
        for port in 1..=LABEL_SELECTORS_MAX {
            write!(
                text,
                "[[ports]]\nprotocol = \"tcp\"\naddress = \"*\"\nport = {port}\nlabel = \"service\"\n"
            )
            .unwrap();
        }
        let config = parse(&text).expect("256 selectors must be accepted");
        assert_eq!(config.labels.len(), LABEL_SELECTORS_MAX);

        let excess = format!(
            "{text}[[ports]]\nprotocol = \"tcp\"\naddress = \"*\"\nport = 257\nlabel = \"excess\"\n"
        );
        let detail = invalid_detail(parse(&excess));
        assert!(detail.contains("more than 256 selectors"), "{detail}");
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
    fn refresh_interval_accepts_both_inclusive_boundaries() {
        let minimum = parse("refresh_interval_seconds = 1").expect("minimum is valid");
        let maximum = parse("refresh_interval_seconds = 3600").expect("maximum is valid");

        assert_eq!(minimum.refresh_interval, Duration::from_secs(1));
        assert_eq!(maximum.refresh_interval, Duration::from_hours(1));
    }

    #[test]
    fn oversized_protected_list_is_rejected() {
        let names: Vec<String> = (0..=PROTECTED_PROCESSES_MAX)
            .map(|index| format!("\"process-{index}\""))
            .collect();
        let text = format!("protected_processes = [{}]", names.join(", "));
        let detail = invalid_detail(parse(&text));
        assert!(detail.contains("maximum"), "detail: {detail}");
        // The bound covers defaults + configured names, but the user only
        // sees their own file: the message must break the count down so the
        // total is not a mystery.
        assert!(detail.contains("configured plus"), "detail: {detail}");
        assert!(detail.contains("built-in defaults"), "detail: {detail}");
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
    fn absent_default_config_yields_defaults() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock must be after the epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "kickoutchi-absent-default-config-{}-{unique}",
            std::process::id(),
        ));
        fs::create_dir(&directory).expect("test directory must be created");
        let path = directory.join("config.toml");

        let config = Config::load_default(Some(path)).expect("an absent default is valid");

        assert_eq!(config.refresh_interval, Config::default().refresh_interval);
        assert_eq!(config.default_sort, Config::default().default_sort);
        assert_eq!(
            config.protected_processes,
            Config::default().protected_processes
        );
        fs::remove_dir(directory).expect("test directory must be removed");
    }

    #[test]
    fn config_reader_accepts_exact_byte_limit() {
        let bytes = vec![b' '; CONFIG_FILE_MAX_BYTES];
        let text = read_config_from(bytes.as_slice(), Path::new("boundary.toml"))
            .expect("boundary-sized config must be accepted");
        assert_eq!(text.len(), CONFIG_FILE_MAX_BYTES);
    }

    #[test]
    fn config_reader_rejects_one_byte_over_limit() {
        let path = std::env::temp_dir().join(format!(
            "kickoutchi-oversized-config-{}.toml",
            std::process::id(),
        ));
        fs::write(&path, vec![b' '; CONFIG_FILE_MAX_BYTES + 1])
            .expect("oversized config fixture must be written");

        let detail = match Config::load(Some(&path)) {
            Err(ConfigError::Invalid { detail, .. }) => detail,
            other => panic!("expected oversized ConfigError::Invalid, got {other:?}"),
        };
        assert!(detail.contains("65536-byte limit"), "detail: {detail}");
        fs::remove_file(path).expect("oversized config fixture must be removed");
    }

    #[test]
    fn config_reader_stops_after_limit_plus_one_bytes() {
        let detail = match read_config_from(std::io::repeat(b' '), Path::new("endless.toml")) {
            Err(ConfigError::Invalid { detail, .. }) => detail,
            other => panic!("expected oversized ConfigError::Invalid, got {other:?}"),
        };
        assert!(detail.contains("exceeds"), "detail: {detail}");
    }

    #[test]
    fn config_reader_reports_an_error_after_a_successful_prefix() {
        struct FailedReader;

        impl Read for FailedReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::ConnectionReset, "lost input"))
            }
        }

        let reader = io::Cursor::new(b"refresh_interval_seconds = 3\n").chain(FailedReader);
        let path = Path::new("interrupted.toml");
        let error = read_config_from(reader, path).expect_err("trailing read failure must win");

        match error {
            ConfigError::Read {
                path: error_path,
                source,
            } => {
                assert_eq!(error_path, path);
                assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
                assert_eq!(source.to_string(), "lost input");
            }
            ConfigError::Invalid { .. } => panic!("expected ConfigError::Read"),
        }
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
