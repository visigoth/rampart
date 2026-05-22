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
brew tap visigoth/rampart
brew install rampart
```

or in one step:

```sh
brew install visigoth/rampart/rampart
```

The tap lives at [github.com/visigoth/homebrew-rampart](https://github.com/visigoth/homebrew-rampart);
brew strips the `homebrew-` prefix automatically.

### One-line installer

```sh
curl -fsSL https://raw.githubusercontent.com/visigoth/rampart/main/install.sh | bash
# or, pin a version and/or change the prefix:
curl -fsSL https://raw.githubusercontent.com/visigoth/rampart/main/install.sh | bash -s -- \
    --version v0.1.0 --prefix /usr/local
```

The script downloads the matching tarball from GitHub Releases, verifies
its sha256, and extracts a prefix-style layout (`bin/rampart`,
`share/man/man1/rampart.1`, `share/rampart/{agents,modules}/`) into the
chosen prefix. Default prefix is `~/.local`, which is user-writable and
on `PATH` by default on most modern distros — no sudo needed.

### From source

```sh
just build         # build into .build/rampart/rampart
just test          # run unit + contract tests
just install       # codesign + install to ~/.local (override via $RAMPART_PREFIX)
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

- bash installer / `just install` (default prefix) → `~/.local/bin/rampart` + `~/.local/share/rampart/...`
- Homebrew → `$(brew --prefix)/bin/rampart` + `$(brew --prefix)/share/rampart/...`
- `RAMPART_PREFIX=/usr/local just install` → system-wide
- `RAMPART_SHARE_DIR=/wherever` overrides the runtime lookup for tests
  or bespoke layouts

### User override layer

`~/.local/share/rampart/{agents,modules}/` is also the canonical place
for user-managed overrides — drop a same-named file there and the
registry picks it up before the bundled copy.

For installs whose prefix is *not* `~/.local` (Homebrew, `/usr/local`,
or any other directory you pass via `RAMPART_PREFIX`), the user-override
layer is genuinely separate from the install share dir, and your edits
there survive every reinstall and upgrade.

For installs whose prefix *is* `~/.local` (the default for `just
install` and the bash installer), the user-override layer and the
install share dir are the same directory. Your hand edits live
alongside the bundled library — and get overwritten the next time
`just install` or the bash installer wipes-and-repopulates that tree.
For durable customizations under this layout, keep your overrides
under `<git-root>/.rampart/{agents,modules}/` (repo-local, wins over
both global tiers) or in a personal dotfiles repo you re-symlink after
each install.

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
