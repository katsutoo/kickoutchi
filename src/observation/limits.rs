//! Central bounds for collection, retention, and serialization.
//!
//! Native adapters import these constants so each limit and its overflow policy
//! are documented together.

// Every limit states its overflow policy. "Fails closed" returns an operational
// error when truncation could produce a wrong answer. "Degrades" drops optional
// enrichment and records an evidence gap.

/// Bytes read from one native socket table (`/proc/net/*`, IP Helper).
///
/// Generous at ~100k sockets. Fails closed: a socket table is the one native
/// source that must never truncate, because dropping bytes removes socket rows
/// while leaving a table that appears complete.
#[allow(
    dead_code,
    reason = "unused on macOS, whose process-first collection has no socket table"
)]
pub(crate) const NATIVE_SOCKET_TABLE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Socket observations retained in one snapshot. Fails closed.
pub(crate) const SOCKET_OBSERVATIONS_MAX: usize = 262_144;

/// Distinct PIDs considered as candidate socket owners in one pass.
///
/// The kernel's own `pid_max` (4 M) already bounds a `/proc` scan, but the
/// bound is stated explicitly so Linux and macOS share one number. Fails
/// closed: silently dropping PIDs can drop a real port owner.
pub(crate) const CANDIDATE_PROCESS_IDS_MAX: usize = 131_072;

/// Aggregate file-descriptor entries traversed per collection scope.
///
/// One million covers ordinary high-density hosts while bounding the
/// multiplicative `PIDs x descriptors` walk. Fails closed: a partial owner map
/// is misleading, not merely incomplete.
#[allow(
    dead_code,
    reason = "unused on Windows, which reads owner PIDs from the IP Helper table"
)]
pub(crate) const FILE_DESCRIPTOR_ENTRIES_MAX: usize = 1_048_576;

/// Socket-to-owner edges retained per association pass.
///
/// Above the socket-table size on purpose, so substantial shared-socket fanout
/// (fork-inherited listeners, `SO_REUSEPORT`) is representable. Fails closed.
pub(crate) const OWNER_EDGES_MAX: usize = 262_144;

/// Process identity reads per consistency attempt, and across both attempts.
///
/// The pair exists so one pathological attempt cannot spend the whole budget
/// and starve the retry. Both fail closed.
pub(super) const PROCESS_IDENTITY_READS_PER_ATTEMPT_MAX: usize = 262_144;
pub(super) const PROCESS_IDENTITY_READS_TOTAL_MAX: usize = 524_288;

/// Rows the legacy `PortEntry` projection may emit. Fails closed.
pub(super) const DERIVED_PORT_ENTRIES_MAX: usize = 262_144;

/// Owners serialized per owner set; the remainder becomes
/// `omitted_owner_count`. Degrades, because the count keeps the omission
/// truthful.
pub(crate) const SERIALIZED_OWNERS_MAX: usize = 64;

/// Distinct reasons an owner set may carry. Fails closed: a ninth reason means
/// the caller is constructing completeness from something other than the fixed
/// evidence vocabulary.
pub(crate) const OWNER_COMPLETENESS_REASONS_MAX: usize = 8;

/// Process and parent-process name bytes. Degrades to `null` plus a metadata
/// gap. Also the width of the CLI table's padding buffer (see `output.rs`).
pub(crate) const PROCESS_NAME_MAX_BYTES: usize = 4 * 1024;

/// Executable path bytes. Degrades to `null` plus a metadata gap.
pub(crate) const EXECUTABLE_PATH_MAX_BYTES: usize = 128 * 1024;

/// Command-line bytes in the legacy list profile.
///
/// Degrades to `null` plus a metadata gap, never to a prefix, because half a
/// command line invites a wrong reading of what a process is doing.
pub(crate) const PROCESS_COMMAND_LINE_MAX_BYTES: usize = 1024 * 1024;

/// Aggregate optional metadata retained across one snapshot. Degrades: later
/// values are omitted before allocation while identities and sockets survive.
pub(crate) const OPTIONAL_METADATA_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Bytes of one fresh process name read at a termination gate. Fails closed:
/// protection policy is decided from this name, so a truncated one could clear
/// a gate the full name would have failed.
pub(crate) const PROTECTION_NAME_MAX_BYTES: usize = 4 * 1024;

/// Members and aggregate name bytes in one bounded protection-evidence scope.
/// Both fail closed for the same reason as the name bound above.
pub(crate) const PROTECTION_SCOPE_MAX_MEMBERS: usize = 512;
pub(crate) const PROTECTION_SCOPE_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Collection attempts before an unstable observation is reported as raced.
///
/// Two, not "until stable": a host whose socket table never settles must
/// report that fact instead of spinning until two reads agree.
pub(super) const CONSISTENCY_ATTEMPTS_MAX: usize = 2;

/// Retries when a native API reports that its output buffer grew between the
/// size query and the read. Fails closed after the third attempt.
#[allow(
    dead_code,
    reason = "unused on Linux, whose procfs reads size themselves"
)]
pub(crate) const NATIVE_RESIZE_ATTEMPTS_MAX: usize = 3;

/// Evidence gaps retained per snapshot; the remainder becomes
/// `omitted_evidence_gap_count`. Degrades, but omission forces the snapshot to
/// partial so the loss can never be mistaken for completeness.
pub(crate) const EVIDENCE_GAPS_MAX: usize = 4_096;

/// Bytes of one evidence or gap message. Truncated on a char boundary: these
/// are explanatory prose, not facts a consumer parses.
pub(crate) const EVIDENCE_MESSAGE_MAX_BYTES: usize = 512;

/// Bytes of an observation-scope identifier. Degrades to `null` plus a scope
/// gap rather than retaining a prefix that could read as a different namespace.
pub(crate) const SCOPE_IDENTIFIER_MAX_BYTES: usize = 256;

/// Distinct scope limitations. Fails closed, like the owner-reason bound.
pub(crate) const SCOPE_LIMITATIONS_MAX: usize = 8;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ObservationLimits {
    pub(super) sockets: usize,
    pub(super) candidate_pids: usize,
    pub(super) owner_edges: usize,
    pub(super) identity_reads_per_attempt: usize,
    pub(super) identity_reads_total: usize,
    pub(super) evidence_gaps: usize,
    pub(super) optional_metadata_bytes: usize,
}

impl ObservationLimits {
    pub(super) const PRODUCTION: Self = Self {
        sockets: SOCKET_OBSERVATIONS_MAX,
        candidate_pids: CANDIDATE_PROCESS_IDS_MAX,
        owner_edges: OWNER_EDGES_MAX,
        identity_reads_per_attempt: PROCESS_IDENTITY_READS_PER_ATTEMPT_MAX,
        identity_reads_total: PROCESS_IDENTITY_READS_TOTAL_MAX,
        evidence_gaps: EVIDENCE_GAPS_MAX,
        optional_metadata_bytes: OPTIONAL_METADATA_MAX_BYTES,
    };
}
