use std::fs;
use std::path::Path;

fn read(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

#[test]
fn nix_is_linux_only_and_derives_the_cargo_version() {
    let flake = read("flake.nix");

    assert!(flake.contains("\"x86_64-linux\""));
    assert!(flake.contains("\"aarch64-linux\""));
    assert!(
        !flake.contains("darwin"),
        "Nix must not advertise Darwin outputs"
    );
    assert!(flake.contains("builtins.fromTOML (builtins.readFile ./Cargo.toml)"));
    assert!(flake.contains("version = cargoPackage.package.version;"));
}

#[test]
fn distribution_profile_strips_symbols_and_preserves_unwinding() {
    let manifest = toml::from_str::<toml::Value>(&read("Cargo.toml"))
        .expect("Cargo.toml must remain valid TOML");
    let distribution = manifest
        .get("profile")
        .and_then(|profile| profile.get("dist"))
        .and_then(toml::Value::as_table)
        .expect("Cargo.toml must define profile.dist");

    assert_eq!(
        distribution.get("strip").and_then(toml::Value::as_str),
        Some("symbols"),
        "distribution binaries must not retain symbol tables",
    );
    assert_eq!(
        distribution.get("panic").and_then(toml::Value::as_str),
        Some("unwind"),
        "distribution binaries must preserve panic cleanup and TUI restoration",
    );
}

/// Fast host-side coverage for the release fields most often updated together.
/// CI separately compares complete `makepkg --printsrcinfo` output in Arch.
/// Package metadata is deliberately compared with its own PKGBUILD rather than
/// Cargo.toml because it remains pinned to the latest published release.
#[test]
fn arch_srcinfo_version_and_checksums_match_pkgbuild() {
    let directory = "packaging/arch/kickoutchi-bin";
    let pkgbuild = read(format!("{directory}/PKGBUILD"));
    let srcinfo = read(format!("{directory}/.SRCINFO"));

    let pkgbuild_version = pkgbuild
        .lines()
        .find_map(|line| line.trim().strip_prefix("pkgver="))
        .unwrap_or_else(|| panic!("{directory}/PKGBUILD declares no pkgver"))
        .trim();
    let srcinfo_version = srcinfo
        .lines()
        .find_map(|line| line.trim().strip_prefix("pkgver = "))
        .unwrap_or_else(|| panic!("{directory}/.SRCINFO declares no pkgver"))
        .trim();
    assert_eq!(
        pkgbuild_version, srcinfo_version,
        "{directory}/.SRCINFO is stale; regenerate it with `makepkg --printsrcinfo > .SRCINFO`",
    );

    let checksums = |text: &str| {
        text.split(|ch: char| !ch.is_ascii_hexdigit())
            .filter(|token| token.len() == 64)
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>()
    };
    let pkgbuild_checksums = checksums(&pkgbuild);
    assert!(
        !pkgbuild_checksums.is_empty(),
        "{directory}/PKGBUILD declares no sha256 checksums",
    );
    assert_eq!(
        pkgbuild_checksums,
        checksums(&srcinfo),
        "{directory}/.SRCINFO checksums do not match its PKGBUILD; regenerate it",
    );
}
