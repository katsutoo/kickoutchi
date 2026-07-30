//! Host-independent validation for release-archive member paths.
//!
//! Raw bytes remain untrusted until their UTF-8 and portable path shape have
//! both been validated, preventing extraction behavior from varying by host.

/// Validate and canonicalize one release-archive member path.
///
/// Archive readers pass raw bytes so invalid UTF-8 cannot be normalized into a
/// different path. Both TAR and ZIP use forward slashes in their portable
/// member names; accepting platform separators would make validation depend on
/// the extraction host.
pub(crate) fn safe_member_name(raw: &[u8], directory: bool) -> Result<String, String> {
    let original =
        std::str::from_utf8(raw).map_err(|_| "archive member path is not UTF-8".to_owned())?;
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
