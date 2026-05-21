#!/usr/bin/env bash
# rampart installer — downloads the latest release tarball and extracts
# it into a Unix prefix. Intended for use as:
#
#   curl -fsSL https://raw.githubusercontent.com/visigoth/rampart/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/visigoth/rampart/main/install.sh | bash -s -- --prefix ~/.local
#
# Or download and inspect first:
#
#   curl -fsSLO https://raw.githubusercontent.com/visigoth/rampart/main/install.sh
#   less install.sh
#   bash install.sh
#
# What it does:
#  1. Detects OS + architecture.
#  2. Fetches the latest release tag from GitHub (or honours --version).
#  3. Downloads the matching tarball + its sha256 file.
#  4. Verifies the sha256.
#  5. Extracts into ${PREFIX} so the layout is
#       ${PREFIX}/bin/rampart
#       ${PREFIX}/share/man/man1/rampart.1
#       ${PREFIX}/share/rampart/{agents,modules}/
#       ${PREFIX}/share/{zsh,bash-completion,fish}/...
#  6. Prints a one-liner to put ${PREFIX}/bin on PATH if it isn't already.
#
# The binary discovers its bundled library via <exe-dir>/../share/rampart,
# so as long as bin/ and share/ end up siblings under PREFIX, no env var
# is needed.
#
# Default prefix is ~/.local — user-writable, on PATH by default on most
# modern distros, no sudo required. Override with --prefix to install
# system-wide.

set -euo pipefail

OWNER="visigoth"
REPO="rampart"
PREFIX="${HOME}/.local"
VERSION=""
USE_SUDO="auto"

usage() {
    cat <<'USAGE'
Usage: install.sh [--prefix DIR] [--version vX.Y.Z] [--no-sudo]

  --prefix DIR     Install prefix (default: ~/.local).
                   The tarball is laid out so bin/, share/man/, and
                   share/rampart/ all land directly under this dir.
                   Common alternatives: /opt/shaheengandhi, /usr/local.
  --version vX.Y.Z Install a specific release tag (default: latest).
  --no-sudo        Don't elevate to root even if the prefix isn't writable
                   by the current user. Useful when running as root
                   already, or when targeting a user-writable prefix.
  -h, --help       Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)     PREFIX="$2"; shift 2 ;;
        --prefix=*)   PREFIX="${1#*=}"; shift ;;
        --version)    VERSION="$2"; shift 2 ;;
        --version=*)  VERSION="${1#*=}"; shift ;;
        --no-sudo)    USE_SUDO="no"; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "install.sh: unknown arg $1" >&2; usage >&2; exit 1 ;;
    esac
done

die() { echo "install.sh: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have curl  || die "curl is required"
have tar   || die "tar is required"
have shasum || have sha256sum || die "shasum or sha256sum is required"

# Resolve target arch / os to the same naming used by `just release`.
uname_s="$(uname -s)"
uname_m="$(uname -m)"
case "${uname_s}" in
    Darwin) os="darwin" ;;
    Linux)  os="linux" ;;
    *) die "unsupported OS: ${uname_s}" ;;
esac
case "${uname_m}" in
    arm64|aarch64) arch="arm64" ;;
    x86_64|amd64)  arch="amd64" ;;
    *) die "unsupported arch: ${uname_m}" ;;
esac

# Resolve which version to fetch.
if [[ -z "${VERSION}" ]]; then
    echo "==> querying latest rampart release"
    VERSION="$(curl -fsSL \
        "https://api.github.com/repos/${OWNER}/${REPO}/releases/latest" \
        | grep -m1 '"tag_name":' \
        | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
    [[ -n "${VERSION}" ]] || die "couldn't determine latest release"
fi
case "${VERSION}" in
    v*) tag="${VERSION}"; bare="${VERSION#v}" ;;
    *)  tag="v${VERSION}"; bare="${VERSION}" ;;
esac

name="rampart-${bare}-${os}-${arch}"
tarball_url="https://github.com/${OWNER}/${REPO}/releases/download/${tag}/${name}.tar.gz"
sha_url="${tarball_url}.sha256"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

echo "==> downloading ${name}.tar.gz"
curl -fsSL "${tarball_url}" -o "${tmp}/${name}.tar.gz"
curl -fsSL "${sha_url}"     -o "${tmp}/${name}.tar.gz.sha256"

echo "==> verifying sha256"
expected="$(awk '{print $1}' "${tmp}/${name}.tar.gz.sha256")"
if have shasum; then
    actual="$(shasum -a 256 "${tmp}/${name}.tar.gz" | awk '{print $1}')"
else
    actual="$(sha256sum "${tmp}/${name}.tar.gz" | awk '{print $1}')"
fi
[[ "${actual}" == "${expected}" ]] || die "sha256 mismatch (want ${expected}, got ${actual})"

echo "==> extracting"
tar -C "${tmp}" -xzf "${tmp}/${name}.tar.gz"
payload="${tmp}/${name}"
[[ -d "${payload}" ]] || die "extracted payload not found at ${payload}"

# Pick a sudo prefix based on prefix writability.
sudo=""
if [[ "${USE_SUDO}" == "no" ]]; then
    sudo=""
elif [[ -w "${PREFIX}" ]] || ([[ ! -e "${PREFIX}" ]] && [[ -w "$(dirname "${PREFIX}")" ]]); then
    sudo=""
else
    if have sudo; then
        sudo="sudo"
        echo "==> ${PREFIX} not user-writable; will use sudo"
    else
        die "${PREFIX} is not writable and sudo is unavailable"
    fi
fi

echo "==> installing to ${PREFIX}"
${sudo} mkdir -p "${PREFIX}"
# Use a per-subtree copy so the bundled library replaces cleanly without
# nuking unrelated content the user may have under PREFIX.
for sub in bin share; do
    if [[ -d "${payload}/${sub}" ]]; then
        ${sudo} mkdir -p "${PREFIX}/${sub}"
        # Replace rampart-owned dirs wholesale (man page, share/rampart),
        # but otherwise merge (so we don't disturb peer programs in share/).
        ${sudo} cp -R "${payload}/${sub}/." "${PREFIX}/${sub}/"
    fi
done

echo
echo "Installed rampart ${tag} into ${PREFIX}."
echo "Binary: ${PREFIX}/bin/rampart"
echo "Library: ${PREFIX}/share/rampart/{agents,modules}/"

case ":${PATH}:" in
    *":${PREFIX}/bin:"*)
        :
        ;;
    *)
        echo
        echo "Add ${PREFIX}/bin to PATH:"
        echo "  echo 'export PATH=\"${PREFIX}/bin:\$PATH\"' >> ~/.zshrc   # or ~/.bashrc"
        ;;
esac

# Quick smoke check (non-fatal — Gatekeeper may quarantine downloaded
# binaries on macOS; the user might need to `xattr -d com.apple.quarantine`).
if "${PREFIX}/bin/rampart" --version >/dev/null 2>&1; then
    echo
    "${PREFIX}/bin/rampart" --version
else
    echo
    echo "Note: \`${PREFIX}/bin/rampart --version\` didn't run cleanly."
    echo "On macOS this often means Gatekeeper quarantined the binary."
    echo "Try: xattr -d com.apple.quarantine ${PREFIX}/bin/rampart"
fi
