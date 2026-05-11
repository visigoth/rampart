# tooling/beads — the Beads issue tracker CLI (`bd`).
#
# Beads is the local-first issue tracker most projects in this  pin
# their work to. Claude's SessionStart hooks frequently shell out to
# `bd prime` / `bd ready` / `bd list` to recover task context at the
# start of a session; without this module the hooks fail with
# "Operation not permitted" and the session starts without context.
#
# Beads stores state in two places:
#   - <repo>/.beads/      project-scoped database + Unix socket (auto-
#                         server-launched on first bd call). Covered by
#                         the profile's workdir write — no entry here.
#   - ~/.beads/           shared cross-workspace registry, dolt shared
#                         server PID/lock/log files, and the bd-internal
#                         dolt working tree.

variable "beads_dir" {
  type        = string
  default     = "~/.beads"
  description = "Beads' user-level data directory (registry + shared dolt server)."
}

write = [
  "${var.beads_dir}",
]

exec = [
  # Homebrew Cask on Apple Silicon. The Cellar subpath catches the
  # versioned bin/bd that /opt/homebrew/bin/bd symlinks into.
  "/opt/homebrew/bin/bd",
  "/opt/homebrew/Cellar/beads",
  # Homebrew Cask on Intel + the default install dir for manual
  # installs on Linux.
  "/usr/local/bin/bd",
  "/usr/local/Cellar/beads",
  # Linuxbrew default location.
  "/home/linuxbrew/.linuxbrew/bin/bd",
  "/home/linuxbrew/.linuxbrew/Cellar/beads",
]
