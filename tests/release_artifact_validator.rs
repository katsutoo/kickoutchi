use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::str;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tar::Archive;
use xz4rust::{XzDecoder, XzNextBlockResult};
use zip::ZipArchive;

const ARCHIVE_BYTES_MAX: u64 = 256 * 1024 * 1024;
const BINARY_BYTES_MAX: u64 = 256 * 1024 * 1024;
const ARCHIVE_MEMBERS_MAX: usize = 64;
const ARCHIVE_EXPANDED_BYTES_MAX: u64 = 512 * 1024 * 1024;
const XZ_DICTIONARY_BYTES_INITIAL: usize = 8 * 1024 * 1024;
const XZ_DICTIONARY_BYTES_MAX: usize = 64 * 1024 * 1024;
const XZ_INPUT_BUFFER_BYTES: usize = 8192;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const VERSION_OUTPUT_BYTES_MAX: usize = 4096;
const READELF_OUTPUT_BYTES_MAX: usize = 64 * 1024;
const MAXIMUM_GLIBC_VERSION: &[u32] = &[2, 31];
const TEST_TIMEOUT: Duration = Duration::from_mins(20);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const HEX: &[u8; 16] = b"0123456789abcdef";

type ValidationResult<T> = Result<T, String>;

#[derive(Clone, Copy)]
struct NativeTarget {
    triple: &'static str,
    windows: bool,
}

fn native_target(runner_os: &str, runner_arch: &str) -> ValidationResult<NativeTarget> {
    let target = match (runner_os, runner_arch) {
        ("Linux", "X64") => NativeTarget {
            triple: "x86_64-unknown-linux-gnu",
            windows: false,
        },
        ("Linux", "ARM64") => NativeTarget {
            triple: "aarch64-unknown-linux-gnu",
            windows: false,
        },
        ("macOS", "X64") => NativeTarget {
            triple: "x86_64-apple-darwin",
            windows: false,
        },
        ("macOS", "ARM64") => NativeTarget {
            triple: "aarch64-apple-darwin",
            windows: false,
        },
        ("Windows", "X64") => NativeTarget {
            triple: "x86_64-pc-windows-msvc",
            windows: true,
        },
        _ => {
            return Err(format!(
                "unsupported native runner: {runner_os}/{runner_arch}"
            ));
        }
    };
    Ok(target)
}

fn valid_target_triple(target: &str) -> bool {
    let mut component_count = 0usize;
    for component in target.split('-') {
        if component.is_empty()
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return false;
        }
        component_count += 1;
    }
    component_count >= 2
}

fn parse_targets(raw: &str) -> ValidationResult<Vec<String>> {
    let targets: Vec<String> = serde_json::from_str(raw)
        .map_err(|error| format!("targets must be valid JSON: {error}"))?;
    if !(1..=16).contains(&targets.len()) {
        return Err("targets must contain 1..=16 entries".to_owned());
    }
    if targets.iter().any(|target| !valid_target_triple(target)) {
        return Err("targets contain an invalid target triple".to_owned());
    }
    let unique: BTreeSet<&str> = targets.iter().map(String::as_str).collect();
    if unique.len() != targets.len() {
        return Err("targets must be unique".to_owned());
    }
    Ok(targets)
}

fn require_single_native_target(targets: &[String], target: &str) -> ValidationResult<()> {
    if targets.len() == 1 && targets[0] == target {
        return Ok(());
    }
    Err(format!(
        "matrix targets {targets:?} must contain only native runner target {target}; \
         release archives require one matching native execution per job"
    ))
}

fn sha256(path: &Path) -> ValidationResult<String> {
    let mut file = File::open(path)
        .map_err(|error| format!("could not open {} for hashing: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024].into_boxed_slice();
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("could not hash {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

fn verify_checksum(archive: &Path, digest: &str) -> ValidationResult<()> {
    let checksum_path = PathBuf::from(format!("{}.sha256", archive.display()));
    let metadata = fs::symlink_metadata(&checksum_path).map_err(|error| {
        format!(
            "missing regular checksum file for {}: {error}",
            archive.file_name().unwrap_or_default().to_string_lossy()
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "missing regular checksum file for {}",
            archive.file_name().unwrap_or_default().to_string_lossy()
        ));
    }
    if !(1..=1024).contains(&metadata.len()) {
        return Err(format!(
            "checksum file size is outside the approved bound for {}",
            archive.file_name().unwrap_or_default().to_string_lossy()
        ));
    }
    let bytes = fs::read(&checksum_path)
        .map_err(|error| format!("could not read {}: {error}", checksum_path.display()))?;
    let text = str::from_utf8(&bytes)
        .map_err(|_| format!("checksum file is not UTF-8: {}", checksum_path.display()))?;
    if !text.is_ascii() {
        return Err(format!(
            "checksum file is not ASCII: {}",
            checksum_path.display()
        ));
    }
    let records: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
    if records.len() != 1 {
        return Err(format!(
            "checksum file must contain exactly one record for {}",
            archive.file_name().unwrap_or_default().to_string_lossy()
        ));
    }
    let record = records[0];
    if record.len() < 67 {
        return Err(format!(
            "invalid checksum file for {}",
            archive.file_name().unwrap_or_default().to_string_lossy()
        ));
    }
    let (record_digest, remainder) = record.split_at(64);
    let filename = remainder
        .strip_prefix("  ")
        .or_else(|| remainder.strip_prefix(" *"));
    let archive_name = archive.file_name().and_then(|name| name.to_str());
    if !record_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || filename != archive_name
        || !record_digest.eq_ignore_ascii_case(digest)
    {
        return Err(format!(
            "invalid checksum file for {}",
            archive.file_name().unwrap_or_default().to_string_lossy()
        ));
    }
    Ok(())
}

fn safe_member_name(raw: &[u8], directory: bool) -> ValidationResult<String> {
    let original =
        str::from_utf8(raw).map_err(|_| "archive member path is not UTF-8".to_owned())?;
    let name = if directory {
        if original.ends_with("//") {
            return Err(format!("noncanonical archive directory path: {original:?}"));
        }
        original.strip_suffix('/').unwrap_or(original)
    } else {
        if original.ends_with('/') {
            return Err(format!("noncanonical archive file path: {original:?}"));
        }
        original
    };
    let mut parts = name.split('/');
    let first = parts.next().unwrap_or_default();
    if name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name.contains('\0')
        || first.ends_with(':')
        || first.is_empty()
        || first == "."
        || first == ".."
        || parts.any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(format!("unsafe archive member path: {original:?}"));
    }
    Ok(name.to_owned())
}

fn expected_archive_paths(target: &str, windows: bool) -> (BTreeSet<String>, BTreeSet<String>) {
    let suffix = if windows { ".exe" } else { "" };
    let names = [
        "CHANGELOG.md".to_owned(),
        "LICENSE".to_owned(),
        "README.md".to_owned(),
        format!("kickoutchi{suffix}"),
        format!("kick{suffix}"),
    ];
    if windows {
        return (names.into_iter().collect(), BTreeSet::new());
    }
    let root = format!("kickoutchi-{target}");
    (
        names
            .into_iter()
            .map(|name| format!("{root}/{name}"))
            .collect(),
        BTreeSet::from([root]),
    )
}

fn output_file(destination: &Path, name: &str) -> ValidationResult<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination.join(name))
        .map_err(|error| format!("could not create extracted binary {name}: {error}"))
}

fn require_exact_read(copied: u64, expected: u64, name: &str) -> ValidationResult<()> {
    if copied != expected {
        return Err(format!("release member size changed while reading: {name}"));
    }
    Ok(())
}

fn supported_tar_file_type(entry_type: tar::EntryType) -> bool {
    entry_type.is_file() || entry_type.is_contiguous() || entry_type.is_gnu_sparse()
}

struct BoundedReader<R> {
    inner: R,
    remaining: u64,
}

struct CheckedXzReader<R> {
    decoder: Box<XzDecoder<'static>>,
    inner: R,
    input: Box<[u8]>,
    input_consumed: usize,
    input_filled: usize,
    end_of_stream: bool,
}

impl<R: Read> CheckedXzReader<R> {
    fn new(inner: R) -> Self {
        Self {
            decoder: XzDecoder::in_heap_with_alloc_dict_size(
                XZ_DICTIONARY_BYTES_INITIAL,
                XZ_DICTIONARY_BYTES_MAX,
            ),
            inner,
            input: vec![0u8; XZ_INPUT_BUFFER_BYTES].into_boxed_slice(),
            input_consumed: 0,
            input_filled: 0,
            end_of_stream: false,
        }
    }

    fn is_end_of_stream(&self) -> bool {
        self.end_of_stream
    }

    fn into_inner(self) -> (R, Vec<u8>) {
        (
            self.inner,
            self.input[self.input_consumed..self.input_filled].to_vec(),
        )
    }
}

impl<R: Read> Read for CheckedXzReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.end_of_stream {
            return Ok(0);
        }
        loop {
            if self.input_consumed == self.input_filled {
                self.input_filled = self.inner.read(&mut self.input)?;
                self.input_consumed = 0;
                if self.input_filled == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
            }
            let result = self
                .decoder
                .decode(&self.input[self.input_consumed..self.input_filled], output)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let (input_count, output_count, end_of_stream) = match result {
                XzNextBlockResult::NeedMoreData(input_count, output_count) => {
                    (input_count, output_count, false)
                }
                XzNextBlockResult::EndOfStream(input_count, output_count) => {
                    (input_count, output_count, true)
                }
            };
            let available = self.input_filled - self.input_consumed;
            if input_count > available || output_count > output.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XZ decoder returned an out-of-range byte count",
                ));
            }
            self.input_consumed += input_count;
            self.end_of_stream = end_of_stream;
            if output_count != 0 || end_of_stream {
                return Ok(output_count);
            }
            if input_count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XZ decoder made no progress",
                ));
            }
        }
    }
}

impl<R> BoundedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut excess = [0u8; 1];
            return match self.inner.read(&mut excess)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "release archive expanded size is outside the approved bound",
                )),
            };
        }
        let remaining = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let allowed = buffer.len().min(remaining);
        let count = self.inner.read(&mut buffer[..allowed])?;
        self.remaining = self.remaining.saturating_sub(
            u64::try_from(count).map_err(|_| io::Error::other("read size did not fit u64"))?,
        );
        Ok(count)
    }
}

struct ZeroWriter;

impl Write for ZeroWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.iter().any(|byte| *byte != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "release TAR contains nonzero data after its end marker",
            ));
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn verify_xz_stream_padding(mut compressed: File, buffered: &[u8]) -> ValidationResult<()> {
    let mut padding_bytes = buffered.len();
    if buffered.iter().any(|byte| *byte != 0) {
        return Err("release XZ stream contains trailing non-padding data".to_owned());
    }
    let mut buffer = [0u8; 4096];
    loop {
        let count = compressed
            .read(&mut buffer)
            .map_err(|error| format!("could not inspect trailing XZ data: {error}"))?;
        if count == 0 {
            break;
        }
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err("release XZ stream contains trailing non-padding data".to_owned());
        }
        padding_bytes = padding_bytes
            .checked_add(count)
            .ok_or_else(|| "release XZ stream padding size overflowed".to_owned())?;
    }
    if !padding_bytes.is_multiple_of(4) {
        return Err("release XZ stream padding is not a multiple of four bytes".to_owned());
    }
    Ok(())
}

type CheckedTarArchive = Archive<BoundedReader<CheckedXzReader<File>>>;

fn open_checked_tar_archive(archive: &Path) -> ValidationResult<CheckedTarArchive> {
    let file = File::open(archive).map_err(|error| {
        format!(
            "could not open release archive {}: {error}",
            archive.display()
        )
    })?;
    let decoder = CheckedXzReader::new(file);
    Ok(Archive::new(BoundedReader::new(
        decoder,
        ARCHIVE_EXPANDED_BYTES_MAX,
    )))
}

fn finish_checked_tar_archive(bundle: CheckedTarArchive) -> ValidationResult<()> {
    let mut decompressed = bundle.into_inner();
    io::copy(&mut decompressed, &mut ZeroWriter)
        .map_err(|error| format!("could not verify the complete TAR/XZ stream: {error}"))?;
    let decoder = decompressed.into_inner();
    if !decoder.is_end_of_stream() {
        return Err("release XZ stream ended before its verified footer".to_owned());
    }
    let (compressed, buffered) = decoder.into_inner();
    verify_xz_stream_padding(compressed, &buffered)
}

fn preflight_raw_tar_archive(archive: &Path) -> ValidationResult<()> {
    let mut bundle = open_checked_tar_archive(archive)?;
    let entries = bundle
        .entries()
        .map_err(|error| format!("could not read raw release TAR entries: {error}"))?
        .raw(true);
    let mut member_count = 0usize;
    let mut expanded_bytes = 0u64;
    for entry in entries {
        member_count = member_count
            .checked_add(1)
            .ok_or_else(|| "release archive member count overflowed".to_owned())?;
        if member_count > ARCHIVE_MEMBERS_MAX {
            return Err("release archive member count is outside the approved bound".to_owned());
        }
        let mut entry = entry.map_err(|error| format!("could not read raw TAR entry: {error}"))?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_global_extensions()
            || entry_type.is_pax_local_extensions()
        {
            return Err("release TAR contains an unsupported extension record".to_owned());
        }
        expanded_bytes = expanded_bytes
            .checked_add(entry.size())
            .ok_or_else(|| "release archive expanded size overflowed".to_owned())?;
        if expanded_bytes > ARCHIVE_EXPANDED_BYTES_MAX {
            return Err("release archive expanded size is outside the approved bound".to_owned());
        }
        io::copy(&mut entry, &mut io::sink())
            .map_err(|error| format!("could not drain raw TAR entry: {error}"))?;
    }
    if member_count == 0 {
        return Err("release archive member count is outside the approved bound".to_owned());
    }
    finish_checked_tar_archive(bundle)
}

fn extract_tar_binaries(
    archive: &Path,
    destination: &Path,
    target: &str,
    expected_binaries: &BTreeSet<String>,
) -> ValidationResult<BTreeMap<String, PathBuf>> {
    preflight_raw_tar_archive(archive)?;
    let mut bundle = open_checked_tar_archive(archive)?;
    let entries = bundle
        .entries()
        .map_err(|error| format!("could not read release TAR entries: {error}"))?;
    let (expected_files, expected_directories) = expected_archive_paths(target, false);
    let mut selected = BTreeMap::new();
    let mut seen_files = BTreeSet::new();
    let mut seen_directories = BTreeSet::new();
    let mut member_count = 0usize;
    let mut expanded_bytes = 0u64;

    for entry in entries {
        member_count = member_count
            .checked_add(1)
            .ok_or_else(|| "release archive member count overflowed".to_owned())?;
        if member_count > ARCHIVE_MEMBERS_MAX {
            return Err("release archive member count is outside the approved bound".to_owned());
        }
        let mut entry = entry.map_err(|error| format!("could not read TAR entry: {error}"))?;
        let entry_type = entry.header().entry_type();
        let is_directory = entry_type.is_dir();
        let member_name = safe_member_name(&entry.path_bytes(), is_directory)?;
        let member_size = entry.size();
        expanded_bytes = expanded_bytes
            .checked_add(member_size)
            .ok_or_else(|| "release archive expanded size overflowed".to_owned())?;
        if expanded_bytes > ARCHIVE_EXPANDED_BYTES_MAX {
            return Err("release archive expanded size is outside the approved bound".to_owned());
        }
        if is_directory {
            if !seen_directories.insert(member_name.clone()) {
                return Err(format!(
                    "release archive contains a duplicate directory: {member_name}"
                ));
            }
            continue;
        }
        if !supported_tar_file_type(entry_type) {
            return Err(format!(
                "release archive contains a forbidden or unsupported member \
                 ({entry_type:?}): {member_name}"
            ));
        }
        if !seen_files.insert(member_name.clone()) {
            return Err(format!(
                "release archive contains a duplicate member: {member_name}"
            ));
        }
        if !expected_files.contains(&member_name) {
            return Err(format!(
                "release archive contains an unexpected member: {member_name}"
            ));
        }
        let basename = member_name.rsplit('/').next().unwrap_or_default();
        if !expected_binaries.contains(basename) {
            let copied = io::copy(&mut entry, &mut io::sink())
                .map_err(|error| format!("could not verify TAR member {member_name}: {error}"))?;
            require_exact_read(copied, member_size, &member_name)?;
            continue;
        }
        if !(1..=BINARY_BYTES_MAX).contains(&member_size) {
            return Err(format!(
                "release binary size is outside the approved bound: {basename}"
            ));
        }
        let mode = entry
            .header()
            .mode()
            .map_err(|error| format!("release binary mode is invalid for {basename}: {error}"))?;
        if mode & 0o111 == 0 {
            return Err(format!("release binary is not executable: {basename}"));
        }
        let output_path = destination.join(basename);
        let mut output = output_file(destination, basename)?;
        let copied = io::copy(&mut entry, &mut output)
            .map_err(|error| format!("could not extract release binary {basename}: {error}"))?;
        require_exact_read(copied, member_size, basename)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&output_path, fs::Permissions::from_mode(mode & 0o777))
                .map_err(|error| format!("could not set mode for {basename}: {error}"))?;
        }
        selected.insert(basename.to_owned(), output_path);
    }

    if member_count == 0 {
        return Err("release archive member count is outside the approved bound".to_owned());
    }
    if seen_files != expected_files || seen_directories != expected_directories {
        return Err("release archive layout differs from the cargo-dist contract".to_owned());
    }
    finish_checked_tar_archive(bundle)?;
    Ok(selected)
}

fn little_endian_u16(bytes: &[u8], offset: usize) -> ValidationResult<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "release ZIP end-of-central-directory record is malformed".to_owned())?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn zip_entry_count(archive: &Path) -> ValidationResult<usize> {
    let mut file = File::open(archive)
        .map_err(|error| format!("could not open release ZIP {}: {error}", archive.display()))?;
    let size = file
        .seek(SeekFrom::End(0))
        .map_err(|error| format!("could not size release ZIP: {error}"))?;
    let retained = size.min(65_557);
    let retained_i64 = i64::try_from(retained)
        .map_err(|_| "release ZIP suffix size could not be represented".to_owned())?;
    file.seek(SeekFrom::End(-retained_i64))
        .map_err(|error| format!("could not seek release ZIP: {error}"))?;
    let retained_usize = usize::try_from(retained)
        .map_err(|_| "release ZIP suffix size could not be represented".to_owned())?;
    let mut suffix = vec![0u8; retained_usize];
    file.read_exact(&mut suffix)
        .map_err(|error| format!("could not read release ZIP suffix: {error}"))?;
    let signature = b"PK\x05\x06";
    let offset = suffix
        .windows(signature.len())
        .rposition(|window| window == signature)
        .ok_or_else(|| "release ZIP has no valid end-of-central-directory record".to_owned())?;
    if suffix.len() - offset < 22 {
        return Err("release ZIP has no valid end-of-central-directory record".to_owned());
    }
    let disk = little_endian_u16(&suffix, offset + 4)?;
    let central_disk = little_endian_u16(&suffix, offset + 6)?;
    let disk_entries = little_endian_u16(&suffix, offset + 8)?;
    let total_entries = little_endian_u16(&suffix, offset + 10)?;
    let comment_bytes = usize::from(little_endian_u16(&suffix, offset + 20)?);
    if offset + 22 + comment_bytes != suffix.len() {
        return Err("release ZIP end-of-central-directory record is malformed".to_owned());
    }
    if disk != 0 || central_disk != 0 || disk_entries != total_entries {
        return Err("multi-disk release ZIPs are forbidden".to_owned());
    }
    if total_entries == u16::MAX {
        return Err("ZIP64 release archives are outside the approved contract".to_owned());
    }
    Ok(usize::from(total_entries))
}

fn extract_zip_binaries(
    archive: &Path,
    destination: &Path,
    target: &str,
    expected_binaries: &BTreeSet<String>,
) -> ValidationResult<BTreeMap<String, PathBuf>> {
    let entry_count = zip_entry_count(archive)?;
    if !(1..=ARCHIVE_MEMBERS_MAX).contains(&entry_count) {
        return Err("release archive member count is outside the approved bound".to_owned());
    }
    let file = File::open(archive)
        .map_err(|error| format!("could not open release ZIP {}: {error}", archive.display()))?;
    let mut bundle =
        ZipArchive::new(file).map_err(|error| format!("could not read release ZIP: {error}"))?;
    if bundle.len() != entry_count {
        return Err("release ZIP entry count changed while opening the archive".to_owned());
    }
    let (expected_files, expected_directories) = expected_archive_paths(target, true);
    let mut selected = BTreeMap::new();
    let mut seen_files = BTreeSet::new();
    let mut seen_directories = BTreeSet::new();
    let mut expanded_bytes = 0u64;

    for index in 0..entry_count {
        let mut member = bundle
            .by_index(index)
            .map_err(|error| format!("could not read ZIP entry {index}: {error}"))?;
        let is_directory = member.is_dir();
        let member_name = safe_member_name(member.name_raw(), is_directory)?;
        expanded_bytes = expanded_bytes
            .checked_add(member.size())
            .ok_or_else(|| "release archive expanded size overflowed".to_owned())?;
        if expanded_bytes > ARCHIVE_EXPANDED_BYTES_MAX {
            return Err("release archive expanded size is outside the approved bound".to_owned());
        }
        if member.encrypted() {
            return Err(format!(
                "release archive contains an encrypted member: {member_name}"
            ));
        }
        if member.is_symlink() {
            return Err(format!(
                "release archive contains a symbolic link: {member_name}"
            ));
        }
        if member
            .unix_mode()
            .is_some_and(|mode| mode & 0o170_000 != 0 && mode & 0o170_000 != 0o100_000)
            && !is_directory
        {
            return Err(format!(
                "release archive contains an unsupported member type: {member_name}"
            ));
        }
        if is_directory {
            let copied = io::copy(&mut member, &mut io::sink()).map_err(|error| {
                format!("could not verify ZIP directory {member_name}: {error}")
            })?;
            require_exact_read(copied, member.size(), &member_name)?;
            if !seen_directories.insert(member_name.clone()) {
                return Err(format!(
                    "release archive contains a duplicate directory: {member_name}"
                ));
            }
            continue;
        }
        if !seen_files.insert(member_name.clone()) {
            return Err(format!(
                "release archive contains a duplicate member: {member_name}"
            ));
        }
        if !expected_files.contains(&member_name) {
            return Err(format!(
                "release archive contains an unexpected member: {member_name}"
            ));
        }
        let basename = member_name.rsplit('/').next().unwrap_or_default();
        if !expected_binaries.contains(basename) {
            let copied = io::copy(&mut member, &mut io::sink())
                .map_err(|error| format!("could not verify ZIP member {member_name}: {error}"))?;
            require_exact_read(copied, member.size(), &member_name)?;
            continue;
        }
        if !(1..=BINARY_BYTES_MAX).contains(&member.size()) {
            return Err(format!(
                "release binary size is outside the approved bound: {basename}"
            ));
        }
        let output_path = destination.join(basename);
        let mut output = output_file(destination, basename)?;
        let copied = io::copy(&mut member, &mut output)
            .map_err(|error| format!("could not extract release binary {basename}: {error}"))?;
        require_exact_read(copied, member.size(), basename)?;
        selected.insert(basename.to_owned(), output_path);
    }

    if seen_files != expected_files || seen_directories != expected_directories {
        return Err("release archive layout differs from the cargo-dist contract".to_owned());
    }
    Ok(selected)
}

fn read_bounded(mut reader: impl Read, limit: usize) -> ValidationResult<Vec<u8>> {
    let read_limit = u64::try_from(limit)
        .map_err(|_| "output byte limit could not be represented".to_owned())?
        .checked_add(1)
        .ok_or_else(|| "output byte limit overflowed".to_owned())?;
    let mut retained = Vec::with_capacity(limit.saturating_add(1));
    reader
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut retained)
        .map_err(|error| format!("could not read process output: {error}"))?;
    if retained.len() > limit {
        return Err("process output exceeded its byte limit".to_owned());
    }
    Ok(retained)
}

fn parse_glibc_version(tail: &[u8]) -> ValidationResult<Option<Vec<u32>>> {
    if !tail.first().is_some_and(u8::is_ascii_digit) {
        return Ok(None);
    }
    let end = tail
        .iter()
        .position(|byte| !byte.is_ascii_digit() && *byte != b'.')
        .unwrap_or(tail.len());
    if tail
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err("readelf reported a malformed GLIBC symbol version".to_owned());
    }

    let mut components = Vec::new();
    let mut component = None::<u32>;
    for byte in &tail[..end] {
        if *byte == b'.' {
            components.push(
                component.take().ok_or_else(|| {
                    "readelf reported a malformed GLIBC symbol version".to_owned()
                })?,
            );
            continue;
        }
        let digit = u32::from(*byte - b'0');
        component = Some(
            component
                .unwrap_or(0)
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit))
                .ok_or_else(|| "readelf reported an oversized GLIBC symbol version".to_owned())?,
        );
    }
    components.push(
        component.ok_or_else(|| "readelf reported a malformed GLIBC symbol version".to_owned())?,
    );
    if components.len() < 2 {
        return Err("readelf reported a malformed GLIBC symbol version".to_owned());
    }
    while components.len() > 2 && components.last() == Some(&0) {
        components.pop();
    }
    Ok(Some(components))
}

fn maximum_glibc_requirement(output: &str) -> ValidationResult<Vec<u32>> {
    const PREFIX: &[u8] = b"GLIBC_";

    let mut remainder = output.as_bytes();
    let mut maximum: Option<Vec<u32>> = None;
    while let Some(offset) = remainder
        .windows(PREFIX.len())
        .position(|window| window == PREFIX)
    {
        remainder = &remainder[offset + PREFIX.len()..];
        let Some(version) = parse_glibc_version(remainder)? else {
            continue;
        };
        if maximum.as_ref().is_none_or(|current| version > *current) {
            maximum = Some(version);
        }
    }
    maximum.ok_or_else(|| "readelf output contained no parseable GLIBC requirement".to_owned())
}

fn format_numeric_version(version: &[u32]) -> String {
    version
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn validate_glibc_requirements(output: &str) -> ValidationResult<Vec<u32>> {
    let maximum = maximum_glibc_requirement(output)?;
    if maximum.as_slice() > MAXIMUM_GLIBC_VERSION {
        return Err(format!(
            "release binary requires GLIBC_{}, above supported maximum GLIBC_{}",
            format_numeric_version(&maximum),
            format_numeric_version(MAXIMUM_GLIBC_VERSION)
        ));
    }
    Ok(maximum)
}

fn terminate_and_wait(child: &mut Child) -> ValidationResult<ExitStatus> {
    match child.kill() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        Err(error) => return Err(format!("could not terminate child process: {error}")),
    }
    let deadline = Instant::now() + CHILD_CLEANUP_TIMEOUT;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("could not reap child process: {error}"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("child process did not reap after termination".to_owned());
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn wait_with_deadline(
    child: &mut Child,
    timeout: Duration,
    abort: Option<&AtomicBool>,
) -> ValidationResult<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if abort.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            let _status = terminate_and_wait(child)?;
            return Err("child process output exceeded its byte limit".to_owned());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("could not wait for child process: {error}"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _status = terminate_and_wait(child)?;
            return Err("child process exceeded its deadline".to_owned());
        }
        thread::sleep(POLL_INTERVAL);
    }
}

struct BoundedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_bounded_command(
    command: &mut Command,
    description: &str,
    output_limit: usize,
) -> ValidationResult<BoundedCommandOutput> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not execute {description}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{description} stdout pipe was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{description} stderr pipe was unavailable"))?;
    let overflow = Arc::new(AtomicBool::new(false));
    let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
    let stdout_overflow = Arc::clone(&overflow);
    let _stdout_reader = thread::spawn(move || {
        let result = read_bounded(stdout, output_limit);
        if result
            .as_ref()
            .is_err_and(|error| error == "process output exceeded its byte limit")
        {
            stdout_overflow.store(true, Ordering::Release);
        }
        let _result = stdout_sender.send(result);
    });
    let (stderr_sender, stderr_receiver) = mpsc::sync_channel(1);
    let stderr_overflow = Arc::clone(&overflow);
    let _stderr_reader = thread::spawn(move || {
        let result = read_bounded(stderr, output_limit);
        if result
            .as_ref()
            .is_err_and(|error| error == "process output exceeded its byte limit")
        {
            stderr_overflow.store(true, Ordering::Release);
        }
        let _result = stderr_sender.send(result);
    });
    let status_result = wait_with_deadline(&mut child, COMMAND_TIMEOUT, Some(&overflow));
    let stdout = stdout_receiver
        .recv_timeout(CHILD_CLEANUP_TIMEOUT)
        .map_err(|error| format!("{description} stdout reader did not stop: {error}"))??;
    let stderr = stderr_receiver
        .recv_timeout(CHILD_CLEANUP_TIMEOUT)
        .map_err(|error| format!("{description} stderr reader did not stop: {error}"))??;
    Ok(BoundedCommandOutput {
        status: status_result?,
        stdout,
        stderr,
    })
}

fn run_version(binary: &Path, expected_version: &str) -> ValidationResult<()> {
    let description = format!("{} --version", binary.display());
    let output = run_bounded_command(
        Command::new(binary).arg("--version"),
        &description,
        VERSION_OUTPUT_BYTES_MAX,
    )?;
    let stdout = str::from_utf8(&output.stdout)
        .map_err(|_| format!("version output was not UTF-8 for {}", binary.display()))?;
    let stderr = str::from_utf8(&output.stderr)
        .map_err(|_| format!("version stderr was not UTF-8 for {}", binary.display()))?;
    let expected = format!("kickoutchi {expected_version}\n");
    if !output.status.success() || stdout != expected || !stderr.is_empty() {
        return Err(format!(
            "unexpected version output from {}: status={}, stdout={stdout:?}, stderr={stderr:?}",
            binary.display(),
            output.status,
        ));
    }
    Ok(())
}

fn inspect_glibc_abi(binary: &Path) -> ValidationResult<()> {
    let description = format!("readelf --version-info {}", binary.display());
    let output = run_bounded_command(
        Command::new("readelf")
            .arg("--version-info")
            .arg(binary)
            .env("LC_ALL", "C"),
        &description,
        READELF_OUTPUT_BYTES_MAX,
    )?;
    if !output.status.success() {
        return Err(format!(
            "readelf failed for {}: status={}, stdout={:?}, stderr={:?}",
            binary.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = str::from_utf8(&output.stdout)
        .map_err(|_| format!("readelf output was not UTF-8 for {}", binary.display()))?;
    let maximum = validate_glibc_requirements(stdout)
        .map_err(|error| format!("{}: {error}", binary.display()))?;
    println!(
        "validated GLIBC ABI: binary={}, maximum=GLIBC_{}",
        binary.display(),
        format_numeric_version(&maximum)
    );
    Ok(())
}

fn run_archive_journeys(canonical: &Path, short: &Path, runner_os: &str) -> ValidationResult<()> {
    let mut command = Command::new("cargo");
    command
        .args([
            "test",
            "--locked",
            "--all-features",
            "--test",
            "cli_contract",
        ])
        .env("KICKOUTCHI_RELEASE_E2E_REQUIRED", "1")
        .env("KICKOUTCHI_E2E_KICKOUTCHI", canonical)
        .env("KICKOUTCHI_E2E_KICK", short)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let release_container = matches!(
        std::env::var("KICKOUTCHI_RELEASE_CONTAINER").as_deref(),
        Ok("1")
    );
    if runner_os == "Linux" && !release_container {
        command.env("KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES", "1");
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start release archive journeys: {error}"))?;
    let status = wait_with_deadline(&mut child, TEST_TIMEOUT, None)?;
    if !status.success() {
        return Err(format!(
            "release archive journeys failed with status {status}"
        ));
    }
    Ok(())
}

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> ValidationResult<Self> {
        for _attempt in 0..16 {
            let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("{prefix}-{}-{counter}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "could not create temporary directory {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        Err("could not reserve a unique temporary directory".to_owned())
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.path);
    }
}

fn validate_release_artifact(
    distrib_path: &Path,
    targets_json: &str,
    runner_os: &str,
    runner_arch: &str,
) -> ValidationResult<()> {
    let targets = parse_targets(targets_json)?;
    let target = native_target(runner_os, runner_arch)?;
    require_single_native_target(&targets, target.triple)?;
    let distrib = distrib_path
        .canonicalize()
        .map_err(|error| format!("distribution path could not be resolved: {error}"))?;
    if !distrib.is_dir() {
        return Err("distribution path must be a directory".to_owned());
    }
    let suffix = if target.windows { ".zip" } else { ".tar.xz" };
    let archive = distrib.join(format!("kickoutchi-{}{suffix}", target.triple));
    let metadata = fs::symlink_metadata(&archive).map_err(|error| {
        format!(
            "missing regular native release archive {}: {error}",
            archive.display()
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "missing regular native release archive {}",
            archive.display()
        ));
    }
    if !(1..=ARCHIVE_BYTES_MAX).contains(&metadata.len()) {
        return Err("release archive size is outside the approved bound".to_owned());
    }
    let archive_sha256 = sha256(&archive)?;
    verify_checksum(&archive, &archive_sha256)?;
    let executable_suffix = if target.windows { ".exe" } else { "" };
    let expected_binaries = BTreeSet::from([
        format!("kickoutchi{executable_suffix}"),
        format!("kick{executable_suffix}"),
    ]);
    let temporary = TemporaryDirectory::new("kickoutchi-release-e2e")?;
    let binaries = if target.windows {
        extract_zip_binaries(&archive, &temporary.path, target.triple, &expected_binaries)?
    } else {
        extract_tar_binaries(&archive, &temporary.path, target.triple, &expected_binaries)?
    };
    let found: BTreeSet<String> = binaries.keys().cloned().collect();
    if found != expected_binaries {
        return Err(format!(
            "release archive binaries differ: expected {expected_binaries:?}, found {found:?}"
        ));
    }
    let canonical_name = format!("kickoutchi{executable_suffix}");
    let short_name = format!("kick{executable_suffix}");
    let canonical = binaries
        .get(&canonical_name)
        .ok_or_else(|| "canonical release binary was not extracted".to_owned())?;
    let short = binaries
        .get(&short_name)
        .ok_or_else(|| "short release binary was not extracted".to_owned())?;
    if runner_os == "Linux" {
        inspect_glibc_abi(canonical)?;
        inspect_glibc_abi(short)?;
    }
    run_version(canonical, env!("CARGO_PKG_VERSION"))?;
    run_version(short, env!("CARGO_PKG_VERSION"))?;
    run_archive_journeys(canonical, short, runner_os)?;
    println!(
        "validated native release archive: target={}, archive={}, bytes={}, sha256={archive_sha256}",
        target.triple,
        archive.display(),
        metadata.len()
    );
    Ok(())
}

#[test]
#[ignore = "requires cargo-dist output and an explicit native runner contract"]
fn validate_generated_native_archive() {
    let distrib = std::env::var_os("KICKOUTCHI_RELEASE_DISTRIB")
        .map(PathBuf::from)
        .expect("KICKOUTCHI_RELEASE_DISTRIB must identify cargo-dist output");
    let targets = std::env::var("KICKOUTCHI_RELEASE_TARGETS_JSON")
        .expect("KICKOUTCHI_RELEASE_TARGETS_JSON must contain the matrix targets");
    let runner_os = std::env::var("KICKOUTCHI_RELEASE_RUNNER_OS")
        .expect("KICKOUTCHI_RELEASE_RUNNER_OS must identify the native runner OS");
    let runner_arch = std::env::var("KICKOUTCHI_RELEASE_RUNNER_ARCH")
        .expect("KICKOUTCHI_RELEASE_RUNNER_ARCH must identify the native runner architecture");
    validate_release_artifact(&distrib, &targets, &runner_os, &runner_arch)
        .expect("generated native release archive must satisfy the release contract");
}

#[cfg(test)]
mod tests {
    use super::*;
    use lzma_rust2::{XzOptions, XzWriter};
    use tar::{Builder, EntryType, Header};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    const LINUX_TARGET: &str = "x86_64-unknown-linux-gnu";
    const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum TarHostile {
        Traversal,
        Absolute,
        Symlink,
        Hardlink,
        MalformedMode,
        Duplicate,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ZipHostile {
        Traversal,
        Absolute,
        Symlink,
        Duplicate,
    }

    fn temporary_directory(prefix: &str) -> TemporaryDirectory {
        TemporaryDirectory::new(prefix).expect("test temporary directory must be created")
    }

    fn write_tar(path: &Path, executable_mode: u32) {
        let file = File::create(path).expect("test TAR must be created");
        let encoder = XzWriter::new(file, XzOptions::default()).expect("test XZ stream must start");
        let mut builder = Builder::new(encoder);
        let root = format!("kickoutchi-{LINUX_TARGET}");
        let mut directory = Header::new_gnu();
        directory.set_entry_type(EntryType::dir());
        directory.set_mode(0o755);
        directory.set_size(0);
        directory.set_cksum();
        builder
            .append_data(&mut directory, format!("{root}/"), io::empty())
            .expect("test TAR directory must be written");
        for name in ["CHANGELOG.md", "LICENSE", "README.md", "kickoutchi", "kick"] {
            let contents = name.as_bytes();
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::file());
            header.set_mode(if name == "kickoutchi" || name == "kick" {
                executable_mode
            } else {
                0o644
            });
            header.set_size(u64::try_from(contents.len()).expect("fixture size must fit u64"));
            header.set_cksum();
            builder
                .append_data(&mut header, format!("{root}/{name}"), contents)
                .expect("test TAR member must be written");
        }
        let encoder = builder.into_inner().expect("test TAR must finish");
        encoder.finish().expect("test XZ stream must finish");
    }

    fn set_raw_tar_path(header: &mut Header, path: &str) {
        assert!(path.len() <= 100, "test TAR path must fit the name field");
        header.as_mut_bytes()[0..100].fill(0);
        header.as_mut_bytes()[0..path.len()].copy_from_slice(path.as_bytes());
    }

    fn write_hostile_tar(path: &Path, hostile: TarHostile) {
        let file = File::create(path).expect("hostile TAR must be created");
        let encoder = XzWriter::new(file, XzOptions::default()).expect("test XZ stream must start");
        let mut builder = Builder::new(encoder);
        let root = format!("kickoutchi-{LINUX_TARGET}");
        let mut directory = Header::new_gnu();
        directory.set_entry_type(EntryType::dir());
        directory.set_mode(0o755);
        directory.set_size(0);
        directory.set_cksum();
        builder
            .append_data(&mut directory, format!("{root}/"), io::empty())
            .expect("test TAR directory must be written");

        for name in ["CHANGELOG.md", "LICENSE", "README.md", "kickoutchi", "kick"] {
            let is_hostile_member = match hostile {
                TarHostile::Traversal | TarHostile::Absolute => name == "README.md",
                TarHostile::Symlink | TarHostile::Hardlink | TarHostile::MalformedMode => {
                    name == "kick"
                }
                TarHostile::Duplicate => false,
            };
            let contents = if is_hostile_member
                && matches!(hostile, TarHostile::Symlink | TarHostile::Hardlink)
            {
                &b""[..]
            } else {
                name.as_bytes()
            };
            let mut header = Header::new_gnu();
            header.set_entry_type(match hostile {
                TarHostile::Symlink if is_hostile_member => EntryType::symlink(),
                TarHostile::Hardlink if is_hostile_member => EntryType::hard_link(),
                _ => EntryType::file(),
            });
            header.set_mode(if name == "kickoutchi" || name == "kick" {
                0o755
            } else {
                0o644
            });
            header.set_size(u64::try_from(contents.len()).expect("fixture size must fit u64"));
            if matches!(hostile, TarHostile::Symlink | TarHostile::Hardlink) && is_hostile_member {
                header
                    .set_link_name(format!("{root}/kickoutchi"))
                    .expect("test TAR link target must be set");
            }
            let member_path = match hostile {
                TarHostile::Traversal if is_hostile_member => format!("{root}/../README.md"),
                TarHostile::Absolute if is_hostile_member => "/README.md".to_owned(),
                _ => format!("{root}/{name}"),
            };
            set_raw_tar_path(&mut header, &member_path);
            if hostile == TarHostile::MalformedMode && is_hostile_member {
                header.as_mut_bytes()[100..108].copy_from_slice(b"invalid\0");
            }
            header.set_cksum();
            builder
                .append(&header, contents)
                .expect("hostile TAR member must be written");
        }

        if hostile == TarHostile::Duplicate {
            let contents = b"duplicate";
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::file());
            header.set_mode(0o644);
            header.set_size(u64::try_from(contents.len()).expect("fixture size must fit u64"));
            header.set_cksum();
            builder
                .append_data(&mut header, format!("{root}/README.md"), &contents[..])
                .expect("duplicate TAR member must be written");
        }

        let encoder = builder.into_inner().expect("hostile TAR must finish");
        encoder.finish().expect("hostile XZ stream must finish");
    }

    fn write_zip(path: &Path, extra: Option<&str>) {
        let file = File::create(path).expect("test ZIP must be created");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o755);
        for name in [
            "CHANGELOG.md",
            "LICENSE",
            "README.md",
            "kickoutchi.exe",
            "kick.exe",
        ] {
            writer
                .start_file(name, options)
                .expect("test ZIP member must start");
            writer
                .write_all(name.as_bytes())
                .expect("test ZIP member must be written");
        }
        if let Some(name) = extra {
            writer
                .start_file(name, options)
                .expect("extra test ZIP member must start");
            writer
                .write_all(b"extra")
                .expect("extra test ZIP member must be written");
        }
        writer.finish().expect("test ZIP must finish");
    }

    fn write_hostile_zip(path: &Path, hostile: ZipHostile) {
        let file = File::create(path).expect("hostile ZIP must be created");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o755);
        for name in [
            "CHANGELOG.md",
            "LICENSE",
            "README.md",
            "kickoutchi.exe",
            "kick.exe",
        ] {
            if hostile == ZipHostile::Symlink && name == "kick.exe" {
                writer
                    .add_symlink(name, "kickoutchi.exe", options)
                    .expect("hostile ZIP symlink must be written");
                continue;
            }
            let member_name = match hostile {
                ZipHostile::Traversal if name == "README.md" => "../README.md",
                ZipHostile::Absolute if name == "README.md" => "/README.md",
                _ => name,
            };
            writer
                .start_file(member_name, options)
                .expect("hostile ZIP member must start");
            writer
                .write_all(name.as_bytes())
                .expect("hostile ZIP member must be written");
        }
        if hostile == ZipHostile::Duplicate {
            writer
                .start_file("OTHER.txt", options)
                .expect("placeholder ZIP member must start");
            writer
                .write_all(b"duplicate")
                .expect("placeholder ZIP member must be written");
        }
        drop(writer.finish().expect("hostile ZIP must finish"));
        if hostile == ZipHostile::Duplicate {
            let mut bytes = fs::read(path).expect("duplicate ZIP fixture must be readable");
            let mut replacements = 0;
            for offset in 0..=bytes.len() - b"OTHER.txt".len() {
                if bytes[offset..].starts_with(b"OTHER.txt") {
                    bytes[offset..offset + b"README.md".len()].copy_from_slice(b"README.md");
                    replacements += 1;
                }
            }
            assert_eq!(
                replacements, 2,
                "placeholder name must occur in local and central ZIP headers"
            );
            fs::write(path, bytes).expect("duplicate ZIP fixture must be patched");
        }
    }

    fn write_tar_extension(path: &Path) {
        let file = File::create(path).expect("test TAR must be created");
        let encoder = XzWriter::new(file, XzOptions::default()).expect("test XZ stream must start");
        let mut builder = Builder::new(encoder);
        let contents = b"11 path=a\n";
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::new(b'x'));
        header.set_mode(0o644);
        header.set_size(u64::try_from(contents.len()).expect("fixture size must fit u64"));
        header.set_cksum();
        builder
            .append_data(&mut header, "PaxHeader", &contents[..])
            .expect("test TAR extension must be written");
        let encoder = builder.into_inner().expect("test TAR must finish");
        encoder.finish().expect("test XZ stream must finish");
    }

    fn write_oversized_member_count_zip(path: &Path) {
        let file = File::create(path).expect("test ZIP must be created");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for index in 0..=ARCHIVE_MEMBERS_MAX {
            writer
                .start_file(format!("member-{index}"), options)
                .expect("test ZIP member must start");
            writer
                .write_all(b"x")
                .expect("test ZIP member must be written");
        }
        writer.finish().expect("test ZIP must finish");
    }

    fn corrupt_zip_member(path: &Path, name: &str) {
        let file = File::open(path).expect("test ZIP must open");
        let mut archive = ZipArchive::new(file).expect("test ZIP must parse");
        let member = archive.by_name(name).expect("test ZIP member must exist");
        let offset = member.data_start().expect("test ZIP member must have data");
        drop(member);
        drop(archive);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("test ZIP must reopen");
        file.seek(SeekFrom::Start(offset))
            .expect("test ZIP member must be seekable");
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).expect("test ZIP member byte");
        byte[0] ^= 0xff;
        file.seek(SeekFrom::Start(offset))
            .expect("test ZIP member must be seekable");
        file.write_all(&byte).expect("test ZIP member corruption");
    }

    #[test]
    fn targets_require_a_bounded_unique_valid_list() {
        assert_eq!(
            parse_targets(&format!(r#"["{LINUX_TARGET}"]"#)).expect("valid target list"),
            [LINUX_TARGET]
        );
        let maximum: Vec<String> = (0..16).map(|index| format!("arch-{index}")).collect();
        assert_eq!(
            parse_targets(&serde_json::to_string(&maximum).expect("serialize targets"))
                .expect("maximum target list"),
            maximum
        );
        let too_many: Vec<String> = (0..17).map(|index| format!("arch-{index}")).collect();
        assert!(
            parse_targets(&serde_json::to_string(&too_many).expect("serialize targets")).is_err()
        );
        for invalid in [
            "[]",
            r#""not-a-list""#,
            r#"["bad target"]"#,
            r#"["x-y","x-y"]"#,
        ] {
            assert!(parse_targets(invalid).is_err(), "accepted {invalid}");
        }
        assert!(require_single_native_target(&[LINUX_TARGET.to_owned()], LINUX_TARGET).is_ok());
        assert!(
            require_single_native_target(
                &[
                    LINUX_TARGET.to_owned(),
                    "aarch64-unknown-linux-gnu".to_owned()
                ],
                LINUX_TARGET
            )
            .is_err()
        );
    }

    #[test]
    fn member_paths_reject_noncanonical_and_escaping_forms() {
        for invalid in [
            "../kick",
            "/kick",
            "folder/../kick",
            r"C:\kick",
            r"\\host\kick",
            r"folder\kick",
            "folder//kick",
            "folder/./kick",
            "folder/kick/",
        ] {
            assert!(
                safe_member_name(invalid.as_bytes(), false).is_err(),
                "accepted {invalid}"
            );
        }
        assert_eq!(
            safe_member_name(b"folder/", true).expect("canonical directory"),
            "folder"
        );
        assert!(safe_member_name(b"folder//", true).is_err());
        assert!(safe_member_name(b"bad\xff", false).is_err());
    }

    #[test]
    fn checksum_requires_one_record_for_the_exact_archive() {
        let temporary = temporary_directory("kickoutchi-checksum-test");
        let archive = temporary.path.join("artifact.tar.xz");
        fs::write(&archive, b"archive").expect("archive fixture");
        let digest = sha256(&archive).expect("fixture digest");
        let checksum = PathBuf::from(format!("{}.sha256", archive.display()));
        fs::write(&checksum, format!("{digest} *artifact.tar.xz\n")).expect("checksum fixture");
        assert!(verify_checksum(&archive, &digest).is_ok());
        for invalid in [
            format!("{digest} *other.tar.xz\n"),
            format!("{digest}\n"),
            format!("{digest} *artifact.tar.xz\n{digest} *artifact.tar.xz\n"),
            format!("{} *artifact.tar.xz\n", "0".repeat(64)),
        ] {
            fs::write(&checksum, invalid).expect("invalid checksum fixture");
            assert!(verify_checksum(&archive, &digest).is_err());
        }
        fs::write(&checksum, vec![b'x'; 1025]).expect("oversized checksum fixture");
        assert!(verify_checksum(&archive, &digest).is_err());
    }

    #[test]
    fn tar_requires_exact_layout_and_executable_binaries() {
        let temporary = temporary_directory("kickoutchi-tar-test");
        let expected = BTreeSet::from(["kickoutchi".to_owned(), "kick".to_owned()]);
        let archive = temporary.path.join("artifact.tar.xz");
        write_tar(&archive, 0o755);
        let output = temporary.path.join("output");
        fs::create_dir(&output).expect("output directory");
        let binaries = extract_tar_binaries(&archive, &output, LINUX_TARGET, &expected)
            .expect("valid TAR fixture");
        assert_eq!(binaries.keys().cloned().collect::<BTreeSet<_>>(), expected);

        let non_executable = temporary.path.join("non-executable.tar.xz");
        write_tar(&non_executable, 0o644);
        let rejected_output = temporary.path.join("rejected-output");
        fs::create_dir(&rejected_output).expect("rejected output directory");
        assert!(
            extract_tar_binaries(&non_executable, &rejected_output, LINUX_TARGET, &expected)
                .is_err()
        );

        let extension = temporary.path.join("extension.tar.xz");
        write_tar_extension(&extension);
        let extension_output = temporary.path.join("extension-output");
        fs::create_dir(&extension_output).expect("extension output directory");
        let error = extract_tar_binaries(&extension, &extension_output, LINUX_TARGET, &expected)
            .expect_err("TAR extension records must be rejected before preprocessing");
        assert!(error.contains("unsupported extension record"));

        let corrupt = temporary.path.join("corrupt.tar.xz");
        write_tar(&corrupt, 0o755);
        let length = fs::metadata(&corrupt).expect("corrupt TAR metadata").len();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&corrupt)
            .expect("corrupt TAR must open");
        file.seek(SeekFrom::Start(length - 8))
            .expect("XZ footer must be seekable");
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).expect("XZ footer byte");
        byte[0] ^= 0xff;
        file.seek(SeekFrom::Start(length - 8))
            .expect("XZ footer must be seekable");
        file.write_all(&byte).expect("XZ footer corruption");
        let corrupt_output = temporary.path.join("corrupt-output");
        fs::create_dir(&corrupt_output).expect("corrupt output directory");
        assert!(extract_tar_binaries(&corrupt, &corrupt_output, LINUX_TARGET, &expected).is_err());
    }

    #[test]
    fn tar_rejects_hostile_paths_links_modes_and_duplicates() {
        let temporary = temporary_directory("kickoutchi-hostile-tar-test");
        let expected = BTreeSet::from(["kickoutchi".to_owned(), "kick".to_owned()]);
        for (hostile, label, error_fragment) in [
            (
                TarHostile::Traversal,
                "traversal",
                "unsafe archive member path",
            ),
            (
                TarHostile::Absolute,
                "absolute",
                "unsafe archive member path",
            ),
            (
                TarHostile::Symlink,
                "symlink",
                "forbidden or unsupported member",
            ),
            (
                TarHostile::Hardlink,
                "hardlink",
                "forbidden or unsupported member",
            ),
            (
                TarHostile::MalformedMode,
                "malformed-mode",
                "mode is invalid",
            ),
            (TarHostile::Duplicate, "duplicate", "duplicate member"),
        ] {
            let archive = temporary.path.join(format!("{label}.tar.xz"));
            write_hostile_tar(&archive, hostile);
            let output = temporary.path.join(format!("{label}-output"));
            fs::create_dir(&output).expect("hostile TAR output directory must be created");

            let error = extract_tar_binaries(&archive, &output, LINUX_TARGET, &expected)
                .expect_err("hostile TAR fixture must be rejected");
            assert!(
                error.contains(error_fragment),
                "hostile TAR fixture {label} reached the wrong rejection: {error}"
            );
        }
    }

    #[test]
    fn zip_requires_exact_flat_layout() {
        let temporary = temporary_directory("kickoutchi-zip-test");
        let expected = BTreeSet::from(["kickoutchi.exe".to_owned(), "kick.exe".to_owned()]);
        let archive = temporary.path.join("artifact.zip");
        write_zip(&archive, None);
        let output = temporary.path.join("output");
        fs::create_dir(&output).expect("output directory");
        let binaries = extract_zip_binaries(&archive, &output, WINDOWS_TARGET, &expected)
            .expect("valid ZIP fixture");
        assert_eq!(binaries.keys().cloned().collect::<BTreeSet<_>>(), expected);

        let unexpected = temporary.path.join("unexpected.zip");
        write_zip(&unexpected, Some("unexpected"));
        let rejected_output = temporary.path.join("rejected-output");
        fs::create_dir(&rejected_output).expect("rejected output directory");
        assert!(
            extract_zip_binaries(&unexpected, &rejected_output, WINDOWS_TARGET, &expected).is_err()
        );

        let oversized = temporary.path.join("oversized-count.zip");
        write_oversized_member_count_zip(&oversized);
        let oversized_output = temporary.path.join("oversized-output");
        fs::create_dir(&oversized_output).expect("oversized output directory");
        let error = extract_zip_binaries(&oversized, &oversized_output, WINDOWS_TARGET, &expected)
            .expect_err("first excess ZIP member must be rejected");
        assert!(error.contains("member count is outside the approved bound"));

        let corrupt = temporary.path.join("corrupt.zip");
        write_zip(&corrupt, None);
        corrupt_zip_member(&corrupt, "README.md");
        let corrupt_output = temporary.path.join("corrupt-output");
        fs::create_dir(&corrupt_output).expect("corrupt output directory");
        assert!(
            extract_zip_binaries(&corrupt, &corrupt_output, WINDOWS_TARGET, &expected).is_err()
        );
    }

    #[test]
    fn zip_rejects_hostile_paths_symlinks_and_duplicates() {
        let temporary = temporary_directory("kickoutchi-hostile-zip-test");
        let expected = BTreeSet::from(["kickoutchi.exe".to_owned(), "kick.exe".to_owned()]);
        for (hostile, label, error_fragment) in [
            (
                ZipHostile::Traversal,
                "traversal",
                "unsafe archive member path",
            ),
            (
                ZipHostile::Absolute,
                "absolute",
                "unsafe archive member path",
            ),
            (ZipHostile::Symlink, "symlink", "symbolic link"),
            (
                ZipHostile::Duplicate,
                "duplicate",
                "entry count changed while opening",
            ),
        ] {
            let archive = temporary.path.join(format!("{label}.zip"));
            write_hostile_zip(&archive, hostile);
            let output = temporary.path.join(format!("{label}-output"));
            fs::create_dir(&output).expect("hostile ZIP output directory must be created");

            let error = extract_zip_binaries(&archive, &output, WINDOWS_TARGET, &expected)
                .expect_err("hostile ZIP fixture must be rejected");
            assert!(
                error.contains(error_fragment),
                "hostile ZIP fixture {label} reached the wrong rejection: {error}"
            );
        }
    }

    #[test]
    fn process_output_reader_rejects_the_first_excess_byte() {
        assert_eq!(read_bounded(&b"abcd"[..], 4).expect("exact limit"), b"abcd");
        assert!(read_bounded(&b"abcde"[..], 4).is_err());
    }

    #[test]
    fn glibc_parser_selects_the_highest_numeric_requirement() {
        let output = r"
          0x0010: Name: GLIBC_2.9 Flags: none Version: 8
          0x0020: Name: GLIBC_PRIVATE Flags: none Version: 7
          0x0030: Name: GLIBC_2.31.0 Flags: none Version: 6
          004: 2 (GLIBC_2.10) 3 (GLIBC_2.2.5)
        ";
        assert_eq!(
            maximum_glibc_requirement(output).expect("parseable readelf output"),
            [2, 31]
        );
    }

    #[test]
    fn glibc_threshold_accepts_2_31_and_rejects_newer_versions() {
        for accepted in ["GLIBC_2.30.99", "GLIBC_2.31", "GLIBC_2.31.0"] {
            assert!(
                validate_glibc_requirements(accepted).is_ok(),
                "rejected {accepted}"
            );
        }
        for rejected in ["GLIBC_2.31.1", "GLIBC_2.32", "GLIBC_3.0"] {
            let error = validate_glibc_requirements(rejected)
                .expect_err("newer GLIBC requirement must be rejected");
            assert!(error.contains("above supported maximum GLIBC_2.31"));
        }
    }

    #[test]
    fn glibc_parser_rejects_missing_and_malformed_requirements() {
        assert!(maximum_glibc_requirement("GLIBC_PRIVATE").is_err());
        assert!(maximum_glibc_requirement("Name: GLIBC_2").is_err());
        assert!(maximum_glibc_requirement("Name: GLIBC_2.31.future").is_err());
    }

    #[test]
    fn expanded_stream_reader_accepts_the_limit_and_rejects_the_first_excess_byte() {
        let mut exact = BoundedReader::new(&b"abcd"[..], 4);
        let mut output = Vec::new();
        exact
            .read_to_end(&mut output)
            .expect("exact expanded limit");
        assert_eq!(output, b"abcd");

        let mut excess = BoundedReader::new(&b"abcde"[..], 4);
        let mut output = Vec::new();
        assert!(excess.read_to_end(&mut output).is_err());
        assert_eq!(output, b"abcd");
    }

    #[test]
    fn tar_file_types_match_python_and_cargo_dist_behavior() {
        assert!(supported_tar_file_type(EntryType::file()));
        assert!(supported_tar_file_type(EntryType::contiguous()));
        assert!(supported_tar_file_type(EntryType::new(b'S')));
        assert!(!supported_tar_file_type(EntryType::symlink()));
        assert!(!supported_tar_file_type(EntryType::fifo()));
    }

    #[test]
    fn runner_mapping_rejects_unsupported_pairs() {
        assert_eq!(
            native_target("Windows", "X64")
                .expect("supported runner")
                .triple,
            WINDOWS_TARGET
        );
        assert!(native_target("Windows", "ARM64").is_err());
        assert!(native_target("unknown", "X64").is_err());
    }
}
