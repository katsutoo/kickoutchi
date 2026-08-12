# AUR packaging

Swamp packages for Arch users.

## What lives here

`kickoutchi-bin/` installs the Linux release archive from the GitHub Release.

It ships the `kickoutchi` binary and the `kick` shortcut. The former source-built
`kickoutchi` AUR package has been retired so Arch users have one maintained AUR
package.

Kickoutchi does not check for releases automatically. Update the package
through the AUR helper that installed it.

## Install from the AUR

```sh
yay -S kickoutchi-bin
```

Then:

```sh
kick --version
kick list
```

Update the package through a normal full-system upgrade, or by asking the
configured AUR helper to rebuild that package.

## Maintainer notes

When a new tag ships, update `pkgver` and the checksums in `PKGBUILD` only after the `cargo-dist` GitHub Release assets exist. Do not use placeholder checksums or `SKIP` for the AUR package metadata.

For a new release, keep the package metadata pinned to the latest published assets until the new GitHub Release assets and checksums exist. A version bump pushed before its assets exist gives Arch users a package that cannot build.

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
