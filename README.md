# Rampart

Cross-platform sandbox wrapper for AI coding agents.

Rampart compiles declarative HCL policy into platform-native sandboxes:

- **macOS** — Seatbelt (sandbox-exec) profiles
- **Linux** — bubblewrap + seccomp filters

It also runs an HTTPS-aware MITM proxy so policy can include domain
allowlists for outbound network access, and an interactive escalation
flow for prompts that exceed the agent's policy budget.

## Build

```sh
just build         # build into .build/rampart/rampart
just test          # run unit + contract tests
just install       # codesign + install to /opt/shaheengandhi
```

A self-signed code-signing identity named `Rampart Local Dev` is
recommended on macOS so the MITM CA key in Keychain keeps a stable ACL
across rebuilds. See the Justfile header for setup steps.

`just install` populates `/opt/shaheengandhi/share/rampart/{agents,modules}/`
straight from the binary's embedded `assets/` tree on every install. The
running binary reads from there, with `~/.local/share/rampart/` layered
on top as a user-managed override directory that rampart never writes to.

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
