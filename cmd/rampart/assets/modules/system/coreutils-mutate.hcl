# system/coreutils-mutate — exec on filesystem-mutating coreutils.
#
# Companion to system/coreutils. The base coreutils module is
# deliberately limited to read-only / pure-function tools so a
# profile can grant "scripts can compute and inspect" without
# implicitly granting "scripts can modify the filesystem". This
# module is the explicit opt-in for the mutating side.
#
# Required for any agent whose workflow includes:
#
#   - Atomic file replacement (mktemp + write + mv).
#   - Hook scripts that clean up after themselves (rm).
#   - Build glue that creates dirs (mkdir) or fixes permissions
#     (chmod / touch).
#
# Claude Code specifically uses mktemp + rm during its
# ~/.claude.json atomic-write cycle on every config flush, and
# user hooks under ~/.claude/hooks/ commonly invoke cp / mkdir.
# The actual write path constraints still apply — these grants
# are exec-only; mutating these binaries doesn't bypass the
# sandbox's filesystem write rules.

exec = [
  # Remove.
  "/bin/rm",
  "/usr/bin/rm",
  "/bin/rmdir",
  "/usr/bin/rmdir",
  # Copy + move.
  "/bin/cp",
  "/usr/bin/cp",
  "/bin/mv",
  "/usr/bin/mv",
  # Create / touch.
  "/bin/mkdir",
  "/usr/bin/mkdir",
  "/usr/bin/mktemp",
  "/usr/bin/touch",
  # Symlinks + hard links.
  "/bin/ln",
  "/usr/bin/ln",
  # Permissions + ownership.
  "/bin/chmod",
  "/usr/bin/chmod",
  "/usr/bin/chown",
  "/usr/sbin/chown",
  # GNU coreutils (gtimeout, ginstall, etc.) are shipped by Homebrew
  # under /opt/homebrew/Cellar/coreutils/<version>/bin/g*. Grant
  # those via system/homebrew rather than enumerating per-tool here.
]
