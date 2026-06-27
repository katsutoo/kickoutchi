# Arch Packaging

This directory contains AUR package templates for Kickoutchi.

## Packages

- `kickoutchi/PKGBUILD` builds from the GitHub source archive with Cargo.
- `kickoutchi-bin/PKGBUILD` installs the Linux release archive produced by `cargo-dist`.

Both packages install the canonical `kickoutchi` binary and the short `kick`
binary. Publish `kickoutchi-bin` first, after the matching GitHub Release exists.

## Before Publishing

Replace every `SKIP` checksum with the real release checksum before pushing to the
AUR. The binary package should use the `.sha256` files uploaded next to the
`cargo-dist` archives. The source package should use the GitHub source archive
checksum for the same tag.

Validate from the package directory:

```sh
makepkg --clean --syncdeps --install
namcap PKGBUILD *.pkg.tar.zst
```

`namcap` is optional for local development but required before publishing. Do not
publish either package until the package name, installed file list, checksums, and
license/doc paths have been checked against the final release artifacts.
