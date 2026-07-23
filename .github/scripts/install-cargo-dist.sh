#!/bin/sh

set -eu

version="${DIST_VERSION:?DIST_VERSION is required}"
os="$(uname -s)"
architecture="$(uname -m)"

case "${os}-${architecture}" in
    Darwin-arm64 | Darwin-aarch64)
        archive="cargo-dist-aarch64-apple-darwin.tar.xz"
        expected_sha256="${DIST_MACOS_AARCH64_SHA256:?DIST_MACOS_AARCH64_SHA256 is required}"
        ;;
    Darwin-x86_64)
        archive="cargo-dist-x86_64-apple-darwin.tar.xz"
        expected_sha256="${DIST_MACOS_X86_64_SHA256:?DIST_MACOS_X86_64_SHA256 is required}"
        ;;
    Linux-aarch64 | Linux-arm64)
        if ldd --version 2>&1 | grep -q musl; then
            archive="cargo-dist-aarch64-unknown-linux-musl.tar.xz"
            expected_sha256="${DIST_LINUX_MUSL_AARCH64_SHA256:?DIST_LINUX_MUSL_AARCH64_SHA256 is required}"
        else
            archive="cargo-dist-aarch64-unknown-linux-gnu.tar.xz"
            expected_sha256="${DIST_LINUX_GNU_AARCH64_SHA256:?DIST_LINUX_GNU_AARCH64_SHA256 is required}"
        fi
        ;;
    Linux-x86_64)
        if ldd --version 2>&1 | grep -q musl; then
            archive="cargo-dist-x86_64-unknown-linux-musl.tar.xz"
            expected_sha256="${DIST_LINUX_MUSL_X86_64_SHA256:?DIST_LINUX_MUSL_X86_64_SHA256 is required}"
        else
            archive="cargo-dist-x86_64-unknown-linux-gnu.tar.xz"
            expected_sha256="${DIST_LINUX_GNU_X86_64_SHA256:?DIST_LINUX_GNU_X86_64_SHA256 is required}"
        fi
        ;;
    *)
        printf 'unsupported cargo-dist host: %s-%s\n' "$os" "$architecture" >&2
        exit 1
        ;;
esac

command -v curl >/dev/null 2>&1
command -v find >/dev/null 2>&1
command -v shasum >/dev/null 2>&1
command -v tar >/dev/null 2>&1

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
download="$temporary_directory/$archive"
curl --proto '=https' --tlsv1.2 -LsSf \
    "https://github.com/axodotdev/cargo-dist/releases/download/v${version}/${archive}" \
    --output "$download"
actual_sha256="$(shasum -a 256 "$download" | awk '{print $1}')"
if [ "$actual_sha256" != "$expected_sha256" ]; then
    printf 'cargo-dist archive checksum mismatch: %s\n' "$actual_sha256" >&2
    exit 1
fi

extracted="$temporary_directory/extracted"
mkdir "$extracted"
tar xf "$download" --strip-components 1 -C "$extracted"
dist_count="$(find "$extracted" -type f -name dist -print | wc -l | tr -d ' ')"
if [ "$dist_count" != 1 ] || [ ! -f "$extracted/dist" ] || [ -L "$extracted/dist" ]; then
    printf 'cargo-dist archive must contain exactly one regular dist executable\n' >&2
    exit 1
fi
bin_directory="${CARGO_HOME:-$HOME/.cargo}/bin"
mkdir -p "$bin_directory"
install -m 755 "$extracted/dist" "$bin_directory/dist"
"$bin_directory/dist" --version

if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$bin_directory" >> "$GITHUB_PATH"
fi
