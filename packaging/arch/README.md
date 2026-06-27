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

These templates are already prepped for the current release. Only the checksums in `PKGBUILD` need updating when a new tag ships. `.SRCINFO` is generated from `PKGBUILD` and must be committed alongside it in the AUR repository.

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
