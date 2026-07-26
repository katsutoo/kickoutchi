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
    assert!(flake.contains("printf '%s\\n' nix"));
}

/// `.SRCINFO` is generated from its `PKGBUILD` and is what the AUR actually
/// indexes, so the two drifting apart publishes a version and checksum set that
/// nobody built. The check is deliberately `PKGBUILD` against its own
/// `.SRCINFO` and never against `Cargo.toml`: package metadata is pinned to the
/// latest *published* release on purpose, so it legitimately lags a version
/// bump until that release's assets exist.
#[test]
fn arch_srcinfo_matches_its_regenerated_pkgbuild() {
    for package in ["kickoutchi", "kickoutchi-bin"] {
        let directory = format!("packaging/arch/{package}");
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
}

#[test]
fn every_manager_package_installs_closed_provenance() {
    for path in [
        "packaging/arch/kickoutchi/PKGBUILD",
        "packaging/arch/kickoutchi-bin/PKGBUILD",
    ] {
        let package = read(path);
        assert!(
            package.contains("install-provenance"),
            "missing marker in {path}"
        );
        assert!(
            package.contains("printf '%s\\n' aur"),
            "wrong marker in {path}"
        );
    }

    let scoop = read("packaging/scoop/bucket/kickoutchi.json");
    assert!(scoop.contains("'install-provenance'"));
    assert!(scoop.contains("-Value 'scoop'"));

    let release = read(".github/workflows/release.yml");
    assert!(release.contains("pkgshare/\\\"install-provenance"));
    assert!(release.contains("write(\\\"homebrew"));
    assert!(release.contains("homebrew/brew@sha256:"));
    assert!(release.contains("docker run --rm"));
    assert!(release.contains("brew install --formula"));
    assert!(release.contains("install-provenance") && release.contains("FORMULA_VERSION"));
    assert!(
        release
            .find("export PATH=\"/home/linuxbrew/.linuxbrew/bin:$PATH\"")
            .expect("Homebrew path must be configured")
            < release
                .find("tap_path=\"$(brew --repository)")
                .expect("canonical tap path must be discovered"),
        "Homebrew must be on PATH before its first invocation"
    );
}
