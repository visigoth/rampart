# Rampart build recipes.
#
# One-time setup (macOS): create a self-signed code-signing identity so
# rebuilds keep a stable signature, which keeps Keychain ACLs (used for
# the MITM CA private key per TR20) consistent across rebuilds.
#
#   1. Open Keychain Access (/System/Applications/Utilities/Keychain Access.app)
#   2. Menu: Keychain Access > Certificate Assistant > Create a Certificate...
#   3. Name: Rampart Local Dev. Identity Type: Self Signed Root.
#      Certificate Type: Code Signing. Override Defaults: optional.
#   4. Verify: security find-identity -v -p codesigning
#      should list "Rampart Local Dev"
#
# Without the cert, install falls back to adhoc signing (-) and Keychain
# will prompt on each rebuild's first MITM CA access.

# Default install prefix is ~/.local so `just install` doesn't need
# sudo and respects the XDG user-install convention. Override with
# `RAMPART_PREFIX=/opt/whatever just install`.
local_prefix := env_var_or_default("RAMPART_PREFIX", env_var("HOME") + "/.local")
local_bin_dir := local_prefix + "/bin"
local_share_dir := local_prefix + "/share"
signing_identity := "Rampart Local Dev"

# Default: list recipes.
default:
    @just --list

# Build the rampart binary into .build/rampart/.
build:
    #!/usr/bin/env bash
    set -euo pipefail
    plist_path="$(pwd)/cmd/rampart/Info.plist"
    install_share_dir="{{ local_share_dir }}/rampart"
    mkdir -p .build/rampart
    # -X main.installShareDir overrides the runtime relative-to-executable
    # lookup so a binary invoked from .build/rampart/ (not the installed
    # location) still finds its library at <prefix>/share/rampart. Installed
    # binaries don't need this — they discover the share dir via
    # <exe-dir>/../share/rampart automatically.
    go build \
        -ldflags="-X main.installShareDir=${install_share_dir} -linkmode external -extldflags=-Wl,-sectcreate,__TEXT,__info_plist,${plist_path}" \
        -o .build/rampart/rampart \
        ./cmd/rampart
    echo "Built: .build/rampart/rampart"

# Build a goreleaser snapshot (single-target darwin/arm64).
snapshot:
    goreleaser build --single-target --snapshot --clean

# Run rampart tests.
test:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "$(uname)" == "Darwin" ]]; then
        plist_path="$(pwd)/cmd/rampart/Info.plist"
        go test \
            -ldflags="-linkmode external -extldflags=-Wl,-sectcreate,__TEXT,__info_plist,${plist_path}" \
            ./cmd/rampart/... ./internal/...
    else
        go test ./cmd/rampart/... ./internal/...
    fi

# Install rampart binary, man page, completions, and bundled library
# (agents + modules) under ~/.local (or $RAMPART_PREFIX if set).
# User-writable prefix, so no sudo unless someone points RAMPART_PREFIX
# at a system path — in which case they can sudo the just call:
#   sudo --preserve-env=RAMPART_PREFIX just install
install: build
    #!/usr/bin/env bash
    set -euo pipefail
    binary=".build/rampart/rampart"
    if security find-identity -v -p codesigning 2>/dev/null | grep -q "{{ signing_identity }}"; then
        identity="{{ signing_identity }}"
        echo "Signing with identity: ${identity}"
    else
        identity="-"
        echo "WARNING: '{{ signing_identity }}' not in Keychain; falling back to adhoc signing."
        echo "         Keychain will reprompt on each rebuild's first MITM CA access."
        echo "         See Justfile header for one-time cert setup."
    fi
    codesign --sign "${identity}" \
        --identifier com.shaheengandhi.rampart \
        --force \
        "${binary}"
    install -d {{ local_bin_dir }}
    install -m 0755 "${binary}" {{ local_bin_dir }}/rampart
    install -d {{ local_share_dir }}/man/man1
    "${binary}" docs man --output-dir /tmp/rampart-man
    install -m 0644 /tmp/rampart-man/rampart.1 {{ local_share_dir }}/man/man1/rampart.1
    rm -rf /tmp/rampart-man
    install -d {{ local_share_dir }}/zsh/site-functions
    "${binary}" completion zsh > {{ local_share_dir }}/zsh/site-functions/_rampart
    install -d {{ local_share_dir }}/bash-completion/completions
    "${binary}" completion bash > {{ local_share_dir }}/bash-completion/completions/rampart
    mkdir -p "${HOME}/.config/fish/completions"
    "${binary}" completion fish > "${HOME}/.config/fish/completions/rampart.fish"
    # Install the bundled rampart library (agents + modules) to the
    # canonical share dir. The binary discovers this directory via its
    # own path: <prefix>/bin/rampart looks up the tree at
    # ../share/rampart automatically.
    #
    # If you install to a prefix OTHER than ~/.local, then
    # ~/.local/share/rampart/ remains a separate user-managed override
    # layer that rampart never writes to. With the default ~/.local
    # prefix the two collapse — your edits live alongside the bundled
    # library and get overwritten on the next `just install`.
    library_src="$(pwd)/cmd/rampart/assets"
    install_share="{{ local_share_dir }}/rampart"
    for sub in agents modules; do
        if [ -d "${library_src}/${sub}" ]; then
            rm -rf "${install_share}/${sub}"
            install -d "${install_share}/${sub}"
            while IFS= read -r f; do
                install -d "${install_share}/${sub}/$(dirname "$f")"
                install -m 0644 "${library_src}/${sub}/$f" "${install_share}/${sub}/$f"
            done < <(cd "${library_src}/${sub}" && find . -type f -name '*.hcl' | sed 's|^\./||')
            count=$(find "${library_src}/${sub}" -type f -name '*.hcl' | wc -l | tr -d ' ')
            echo "Installed: ${install_share}/${sub}/ (${count} files)"
        fi
    done
    echo "Installed: {{ local_bin_dir }}/rampart"

# Cut a release for darwin/arm64. Bumps cmd/rampart/VERSION, tags
# vX.Y.Z, builds a prefix-style tarball, pushes the tag, and creates a
# GitHub release with the tarball attached.
#
# Usage:
#   just release 1.0.0
#   just release 1.0.0-rc1
#
# Requires: gh CLI authenticated against github.com/visigoth/rampart,
# a clean working tree on main, and (optionally) the "Rampart Local Dev"
# signing identity in Keychain. Without that identity the released binary
# is ad-hoc signed, which is enough for local execution and Homebrew
# builds-from-source but means downloaded binaries will fail Gatekeeper.
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    version="{{ VERSION }}"
    if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
        echo "release: version must be X.Y.Z or X.Y.Z-suffix (got: ${version})" >&2
        exit 1
    fi
    tag="v${version}"
    if git rev-parse --verify --quiet "refs/tags/${tag}" >/dev/null; then
        echo "release: tag ${tag} already exists" >&2
        exit 1
    fi
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "release: working tree is dirty; commit or stash first" >&2
        exit 1
    fi
    branch="$(git rev-parse --abbrev-ref HEAD)"
    if [[ "${branch}" != "main" ]]; then
        echo "release: must be on main (currently on ${branch})" >&2
        exit 1
    fi
    if ! command -v gh >/dev/null 2>&1; then
        echo "release: gh CLI is required (https://cli.github.com)" >&2
        exit 1
    fi

    echo "==> running tests"
    just test

    echo "==> bumping VERSION to ${version}"
    printf '%s' "${version}" > cmd/rampart/VERSION
    git add cmd/rampart/VERSION
    if ! git diff --cached --quiet; then
        git commit -m "release: ${tag}"
    fi
    git tag -a "${tag}" -m "rampart ${tag}"

    echo "==> building release binary"
    just build
    binary=".build/rampart/rampart"

    # Sign with the local dev identity if available; ad-hoc otherwise.
    if security find-identity -v -p codesigning 2>/dev/null | grep -q "{{ signing_identity }}"; then
        identity="{{ signing_identity }}"
    else
        identity="-"
        echo "release: WARNING — '{{ signing_identity }}' not in Keychain; using ad-hoc signature"
    fi
    codesign --sign "${identity}" \
        --identifier com.shaheengandhi.rampart \
        --force "${binary}"

    echo "==> assembling tarball"
    rm -rf dist/release
    arch="$(uname -m)"
    case "${arch}" in
        arm64|aarch64) goarch="arm64" ;;
        x86_64|amd64)  goarch="amd64" ;;
        *) echo "release: unsupported arch ${arch}" >&2; exit 1 ;;
    esac
    os="$(uname | tr '[:upper:]' '[:lower:]')"
    payload_name="rampart-${version}-${os}-${goarch}"
    payload="dist/release/${payload_name}"
    mkdir -p "${payload}/bin" \
             "${payload}/share/man/man1" \
             "${payload}/share/zsh/site-functions" \
             "${payload}/share/bash-completion/completions" \
             "${payload}/share/fish/vendor_completions.d" \
             "${payload}/share/rampart"

    cp "${binary}" "${payload}/bin/rampart"
    chmod 0755 "${payload}/bin/rampart"

    "${binary}" docs man --output-dir "${payload}/share/man/man1"
    "${binary}" completion zsh  > "${payload}/share/zsh/site-functions/_rampart"
    "${binary}" completion bash > "${payload}/share/bash-completion/completions/rampart"
    "${binary}" completion fish > "${payload}/share/fish/vendor_completions.d/rampart.fish"

    # Copy the bundled library straight from source. Tarball install:
    # extract into <prefix>/, and the binary's relative-to-executable
    # lookup finds <prefix>/share/rampart/{agents,modules}/.
    rsync -a --include='*/' --include='*.hcl' --exclude='*' \
        cmd/rampart/assets/agents/ "${payload}/share/rampart/agents/"
    rsync -a --include='*/' --include='*.hcl' --exclude='*' \
        cmd/rampart/assets/modules/ "${payload}/share/rampart/modules/"

    cp README.md "${payload}/README.md"
    if [ -f LICENSE ]; then
        cp LICENSE "${payload}/LICENSE"
    fi

    tarball="dist/release/${payload_name}.tar.gz"
    (cd dist/release && tar -czf "${payload_name}.tar.gz" "${payload_name}")
    sha256="$(shasum -a 256 "${tarball}" | awk '{print $1}')"
    echo "==> ${tarball}"
    echo "    sha256: ${sha256}"
    echo "${sha256}  ${payload_name}.tar.gz" > "dist/release/${payload_name}.tar.gz.sha256"

    echo "==> pushing tag to origin"
    git push origin main
    git push origin "${tag}"

    echo "==> creating GitHub release"
    gh release create "${tag}" \
        --title "rampart ${tag}" \
        --notes "Release ${tag}. See CHANGELOG.md or the commit log for details." \
        "${tarball}" \
        "dist/release/${payload_name}.tar.gz.sha256"

    echo
    echo "Released ${tag}. Tarball at ${tarball} (sha256 ${sha256})."
    echo
    echo "Next: bump the tap formula in the homebrew-rampart repo."
    echo "  url     https://github.com/visigoth/rampart/archive/refs/tags/${tag}.tar.gz"
    echo "  sha256  $(curl -fsSL https://github.com/visigoth/rampart/archive/refs/tags/${tag}.tar.gz 2>/dev/null | shasum -a 256 | awk '{print \$1}')"
    echo "  version ${version}"

# Tidy go module dependencies.
tidy:
    go mod tidy

# Run go vet.
vet:
    go vet ./...

# Remove build artifacts.
clean:
    rm -rf .build dist
