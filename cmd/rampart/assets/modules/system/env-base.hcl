# system/env-base — the minimum environment-variable passthrough set
# every sandboxed process expects from a POSIX shell login.
#
# Before this module existed, these names were hardcoded in the
# rampart binary as the implicit "always passed" set. Moving them
# into a module makes the passthrough surface explicit in the policy
# — every var traces to a `use` line in some profile and a matching
# `env` declaration on the agent. Profiles that don't want any of
# this default surface simply don't `use` this module.
#
# Rationale per entry:
#   PATH       — every exec lookup depends on it.
#   HOME       — config files, ~/.cache, ~/.config, ~/.local.
#   USER       — git author, prompt expansion, sudo identity probes.
#   TERM       — terminal capability detection (curses, less, vim).
#   LANG       — character set and message language fallback.
#   SHELL      — script interpreters falling back to the user shell.
#   TMPDIR     — preferred scratch space (vs. /tmp).
#   XDG_*_HOME / XDG_RUNTIME_DIR — XDG Base Directory paths.
#   SSH_AUTH_SOCK — ssh-agent integration is a pervasive shell
#                   expectation. The socket file itself is gated at
#                   the filesystem layer; the env var is just a path.
#   LC_*       — locale variants (LC_ALL, LC_TIME, LC_CTYPE, …).

env = [
  "PATH",
  "HOME",
  "USER",
  "TERM",
  "LANG",
  "SHELL",
  "TMPDIR",
  "XDG_*",
  "SSH_AUTH_SOCK",
  "LC_*",
]
