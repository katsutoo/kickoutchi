# AUR packaging

Swamp packages for Arch users.

## What lives here

- `kickoutchi-bin/` installs the Linux release archive from the GitHub Release.
- `kickoutchi/` builds the same thing from the release source archive with Cargo.

Both ship the `kickoutchi` binary and the `kick` shortcut. The `-bin` package is the quick path; the source package is for folks who want to compile their own onion layers.

## Install from the AUR

Once the packages are live:

```sh
yay -S kickoutchi-bin
```

Or build the source version:

```sh
yay -S kickoutchi
```

Then:

```sh
kick --version
kick list
```

## Maintainer notes

When a new tag ships, update `pkgver` and the checksums in `PKGBUILD` only after the `cargo-dist` GitHub Release assets exist. Do not use placeholder checksums or `SKIP` for the AUR package metadata.

For a new release, keep the package metadata pinned to the latest published assets until the new GitHub Release assets and checksums exist. Publishing to AUR still waits until account creation is open again.

The required update order is: run/publish the release with `cargo-dist`, download or read the generated checksums from the release assets, update `pkgver`/`source`/`provides`/`sha256sums`, regenerate `.SRCINFO`, then build locally.

Generate `.SRCINFO` after editing a `PKGBUILD`:

```sh
makepkg --printsrcinfo > .SRCINFO
```

Build and check locally:

```sh
makepkg -C --clean --syncdeps --noconfirm -f
PATH=/usr/bin:/bin namcap PKGBUILD *.pkg.tar.zst
```

If `namcap` fusses about `gcc-libs`, ignore it. The release binaries link `libgcc_s`, so the dependency stays.
