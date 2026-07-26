# Scoop bucket

Personal [Scoop](https://scoop.sh) bucket reference for Nuggocto projects and
release artifacts. The live bucket is `nuggocto/scoop-bucket`; this directory is
kept as the source reference inside the Kickoutchi repository.

The live bucket updates itself: Excavator watches stable upstream releases and
commits new versions, URLs, and hashes there on its own (see "How updates happen"
below). This in-repo copy is a bootstrap seed, not the source of truth; if it
lags a release, that is expected and installs are unaffected.

## Usage

The bucket name is local to each machine. These examples use `nuggocto` so the
same bucket can hold multiple apps.

```powershell
scoop bucket add nuggocto https://github.com/nuggocto/scoop-bucket
scoop install kickoutchi

# Later updates
scoop update
scoop update kickoutchi
```

Installs both `kickoutchi.exe` and `kick.exe` from the release's
`x86_64-pc-windows-msvc` archive. Windows on ARM is not shipped (x64 only).

## Packages

| Manifest | Project |
| --- | --- |
| `kickoutchi` | https://github.com/nuggocto/kickoutchi |

More manifests can be added under `bucket/*.json` as other projects publish
Scoop releases.

## Repository Setup

GitHub Actions must be enabled in `nuggocto/scoop-bucket` with **Read and write
permissions** so Excavator can commit manifest updates with the repo's own
`GITHUB_TOKEN`.

## How updates happen

Each manifest can carry `checkver` and `autoupdate` entries so Excavator can
watch upstream GitHub releases, regenerate versions, URLs, and hashes, then
commit the update. The workflow runs every four hours and can also be dispatched
manually. Its write access and `GITHUB_TOKEN` belong to the bucket repository;
the Kickoutchi release workflow does not push Scoop manifests or hold a bucket
credential.

Kickoutchi does not check for releases automatically. Scoop and the bucket's
Excavator workflow remain responsible for discovering and installing updates.

To test a manifest change before pushing:

```powershell
scoop install ./bucket/kickoutchi.json
scoop uninstall kickoutchi
```
