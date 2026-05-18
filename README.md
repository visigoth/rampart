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

## Docs

- `docs/readme.org` — user-facing overview
- `docs/policy.org` — HCL policy reference
- `rampart --help` — CLI reference (also `man rampart` after `just install`)
