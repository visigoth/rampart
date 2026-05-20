# Rampart

Cross-platform sandbox wrapper for AI coding agents.

Rampart compiles declarative HCL policy into platform-native sandboxes:

- **macOS** — Seatbelt (sandbox-exec) profiles
- **Linux** — bubblewrap + seccomp filters

It also runs an HTTPS-aware MITM proxy so policy can include domain
allowlists for outbound network access, and an interactive escalation
flow for prompts that exceed the agent's policy budget.

## Install

### Homebrew

```sh
brew install --formula https://raw.githubusercontent.com/visigoth/rampart/main/Formula/rampart.rb
```

(A proper tap is on the roadmap; this URL form works until then.)

### One-line installer

```sh
curl -fsSL https://raw.githubusercontent.com/visigoth/rampart/main/install.sh | bash
# or, pin a version and prefix:
curl -fsSL https://raw.githubusercontent.com/visigoth/rampart/main/install.sh | bash -s -- \
    --version v0.1.0 --prefix /opt/shaheengandhi
```

The script downloads the matching tarball from GitHub Releases, verifies
its sha256, and extracts a prefix-style layout (`bin/rampart`,
`share/man/man1/rampart.1`, `share/rampart/{agents,modules}/`) into the
chosen prefix.

### From source

```sh
just build         # build into .build/rampart/rampart
just test          # run unit + contract tests
just install       # codesign + install to /opt/shaheengandhi
```

A self-signed code-signing identity named `Rampart Local Dev` is
recommended on macOS so the MITM CA key in Keychain keeps a stable ACL
across rebuilds. See the Justfile header for setup steps.

## How the bundled library lives on disk

Whichever install channel you use, the binary lands at
`<prefix>/bin/rampart` and the bundled agent + module library at
`<prefix>/share/rampart/{agents,modules}/`. At runtime the binary
discovers the library by walking back from its own path
(`<exe-dir>/../share/rampart`), so:

- Homebrew → `$(brew --prefix)/bin/rampart` + `$(brew --prefix)/share/rampart/...`
- bash installer (default prefix) → `/opt/shaheengandhi/bin/rampart` + `/opt/shaheengandhi/share/rampart/...`
- `just install` → same as the bash installer
- `RAMPART_SHARE_DIR=/wherever` overrides the lookup for tests or
  bespoke layouts

`~/.local/share/rampart/{agents,modules}/` is a user-managed override
layer — anything you drop there shadows the same-named bundled file.
Rampart never writes to this directory, so your overrides survive
reinstalls and upgrades.

There is no embedded fallback library in the binary: if no install
share dir is present, the bundled agents and modules genuinely don't
exist for that run. This is a deliberate trade — having the HCL files
on disk means you can read them, grep them, and copy from them when
authoring your own.

## Probing a policy

```sh
rampart test --agent coding --profile myproject/default
```

Drops into an interactive REPL where you can ask the resolved policy
`read`, `write`, `exec`, and `http` verdicts for specific paths and URLs
without actually launching a sandboxed process. Useful for checking
that a profile grants what you expect before committing to it.

## Docs

- `docs/readme.org` — user-facing overview
- `docs/policy.org` — HCL policy reference
- `rampart --help` — CLI reference (also `man rampart` after `just install`)
