#!/bin/sh
# Breach Harbor installer.
#
#   curl -fsSL https://breachharbor.com/install.sh | sh
#
# Downloads the right prebuilt binary for this machine from GitHub
# Releases, verifies its checksum, and installs it to $BINDIR
# (default /usr/local/bin). Safe to re-run to upgrade or reinstall.
#
# Env vars:
#   BREACHHARBOR_VERSION   release tag to install, e.g. v0.2.0 (default: latest)
#   BINDIR                 install directory (default: /usr/local/bin)

set -eu

REPO="Dyneteq/Breach-Harbor"
VERSION="${BREACHHARBOR_VERSION:-latest}"
BINDIR="${BINDIR:-/usr/local/bin}"

log() { printf '%s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found on PATH"
}

need curl
need tar

os="$(uname -s)"
case "$os" in
  Linux) goos="linux" ;;
  Darwin) goos="darwin" ;;
  OpenBSD) goos="openbsd" ;;
  *) die "unsupported OS: $os (see the GitHub Releases page for a manual build)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) goarch="amd64" ;;
  aarch64|arm64) goarch="arm64" ;;
  *) die "unsupported architecture: $arch" ;;
esac

if [ "$goos" = "darwin" ] && [ "$goarch" = "amd64" ]; then
  die "no darwin/amd64 build is published yet; build from source with 'make build' instead"
fi
if [ "$goos" = "openbsd" ] && [ "$goarch" != "amd64" ]; then
  die "no openbsd/$goarch build is published; build from source with 'make build' instead"
fi

if [ "$VERSION" = "latest" ]; then
  api_url="https://api.github.com/repos/${REPO}/releases/latest"
else
  api_url="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi

log "Resolving release ($VERSION)..."
tag="$(curl -fsSL "$api_url" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
[ -n "$tag" ] || die "could not resolve a release tag from $api_url"

asset="breachharbor_${tag}_${goos}_${goarch}"
base_url="https://github.com/${REPO}/releases/download/${tag}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

log "Downloading ${asset}.tar.gz (${tag})..."
curl -fsSL -o "$workdir/${asset}.tar.gz" "${base_url}/${asset}.tar.gz" \
  || die "download failed: ${base_url}/${asset}.tar.gz (no build for ${goos}/${goarch} in ${tag}?)"

log "Verifying checksum..."
curl -fsSL -o "$workdir/checksums.txt" "${base_url}/checksums.txt" \
  || die "could not fetch checksums.txt for ${tag}"

expected="$(grep "${asset}.tar.gz\$" "$workdir/checksums.txt" | awk '{print $1}')"
[ -n "$expected" ] || die "no checksum entry for ${asset}.tar.gz"

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$workdir/${asset}.tar.gz" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$workdir/${asset}.tar.gz" | awk '{print $1}')"
else
  die "need sha256sum or shasum to verify the download"
fi

[ "$expected" = "$actual" ] || die "checksum mismatch for ${asset}.tar.gz (expected $expected, got $actual)"

tar -xzf "$workdir/${asset}.tar.gz" -C "$workdir"

install_bin() {
  src="$1"
  name="$2"
  if [ -w "$BINDIR" ]; then
    cp "$src" "$BINDIR/$name"
    chmod 755 "$BINDIR/$name"
  else
    log "$BINDIR is not writable, using sudo..."
    sudo cp "$src" "$BINDIR/$name"
    sudo chmod 755 "$BINDIR/$name"
  fi
}

mkdir -p "$BINDIR" 2>/dev/null || true
install_bin "$workdir/${asset}/breachharbor" "breachharbor"
install_bin "$workdir/${asset}/breachharbor" "bh"

log ""
log "Installed breachharbor ${tag} to ${BINDIR}/breachharbor (and ${BINDIR}/bh)"
"$BINDIR/breachharbor" version 2>/dev/null || true
log ""
log "Next steps:"
log "  breachharbor doctor          # check what's ready, never needs root"
log "  breachharbor agent flush     # dry-run report, always safe"
