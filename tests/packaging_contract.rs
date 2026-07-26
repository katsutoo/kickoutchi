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
