#!/bin/sh
# Installs authsec-cli (AuthSec Agent Kit) to /usr/local/bin.
#
#   curl -fsSL https://github.com/authsec-ai/authsec-cli/releases/latest/download/install.sh | sudo sh
#
# It downloads the binary for this OS and CPU from the same release as this
# script, checks it against the release's SHA256SUMS, and installs it. Nothing
# else is changed: connect and start the daemon afterwards
# (`authsec-cli connect`, `authsec-cli daemon install`).
#
#   AUTHSEC_CLI_BASE     where the release files are (default: the latest GitHub release)
#   AUTHSEC_CLI_BINDIR   where to install (default /usr/local/bin)
set -eu

BASE="${AUTHSEC_CLI_BASE:-https://github.com/authsec-ai/authsec-cli/releases/latest/download}"
BINDIR="${AUTHSEC_CLI_BINDIR:-/usr/local/bin}"

fail() { echo "authsec-cli install: $*" >&2; exit 1; }

os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported OS $os (Linux and macOS; on Windows download authsec-cli-windows-amd64.exe)" ;;
esac
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported CPU $arch" ;;
esac
[ "$os/$arch" = "darwin/amd64" ] && fail "macOS on Intel is not built; use an Apple silicon Mac or Linux"
name="authsec-cli-$os-$arch"

command -v curl >/dev/null 2>&1 || fail "curl is required"
if command -v sha256sum >/dev/null 2>&1; then sum() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
else fail "sha256sum or shasum is required"; fi

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT INT TERM

echo "downloading $name from $BASE"
curl -fsSL --proto '=https,http' -o "$tmp/$name" "$BASE/$name" || fail "download of $name failed"
curl -fsSL --proto '=https,http' -o "$tmp/SHA256SUMS" "$BASE/SHA256SUMS" || fail "download of SHA256SUMS failed"

want=$(awk -v n="$name" '$2 == n || $2 == "*"n {print $1}' "$tmp/SHA256SUMS")
[ -n "$want" ] || fail "SHA256SUMS has no entry for $name"
got=$(sum "$tmp/$name")
[ "$want" = "$got" ] || fail "checksum mismatch for $name (want $want, got $got): not installed"

mkdir -p "$BINDIR"
install -m 0755 "$tmp/$name" "$BINDIR/authsec-cli" 2>/dev/null || { cp "$tmp/$name" "$BINDIR/authsec-cli" && chmod 0755 "$BINDIR/authsec-cli"; } \
  || fail "cannot write $BINDIR (run with sudo)"
echo "installed $("$BINDIR/authsec-cli" version 2>/dev/null | head -1) to $BINDIR/authsec-cli"
echo "next: sudo authsec-cli connect ... (the console's Add machine shows the command), then sudo authsec-cli daemon install"
