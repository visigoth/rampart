# system/base — minimum surface a typical CLI needs: /etc essentials
# (DNS, hostname, user DB, root CA bundle, timezone) and the standard
# system shells so hooks and shell-pipeline tooling can run.
#
# Most language modules implicitly depend on this. Without the shell
# entries, agents that spawn `sh -c '...'` or run hook scripts fail
# with EPERM at posix_spawn time even though the script's own commands
# are otherwise allowed.

read = [
  "/etc/resolv.conf",
  "/etc/hosts",
  "/etc/passwd",
  "/etc/group",
  "/etc/nsswitch.conf",
  "/etc/localtime",
  "/etc/timezone",
  "/etc/ssl/certs",
  "/etc/ssl/cert.pem",
  "/etc/pki/tls/certs",
  "/usr/share/ca-certificates",

  # PATH-scan directories on the stock system. Every modern launcher
  # (Bun, Node, Go's exec.LookPath, the shell `command -v`) walks
  # PATH entries with readdir(2) to find binaries before exec'ing
  # them. Exec grants on specific binaries (handled by other
  # modules) don't imply read on the parent directory; without
  # these, claude/bun emit one escalation per PATH entry at startup.
  # Homebrew + linuxbrew PATH entries live in system/homebrew —
  # use that module to grant the third-party install prefix.
  "/usr/bin",
  "/bin",
  "/usr/sbin",
  "/sbin",

  # macOS noise-probe paths that every modern runtime touches at
  # startup — Bun (claude), node, swift, etc. all stat / read these
  # via system frameworks. Each one we don't allow becomes a
  # sandbox deny that the auth engine publishes as an escalation,
  # which after the (default 30s) timeout escalates to SIGKILL —
  # killing claude mid-session because nobody approved a noise read.
  # The contents are diagnostic config, not credentials, so a broad
  # read grant is safe.
  "/Library/Preferences/Logging",
  "/Library/Preferences/com.apple.networkd.plist",

  # macOS metadata server (mds) per-uid IPC dir. Anything talking
  # to Spotlight, Quick Look, kMDQueryAttr* or CoreServices'
  # MetadataAvailability framework stats files in here at startup —
  # Bun/Node apps probe se_SecurityMessages specifically.
  # /var/db is a symlink to /private/var/db on macOS; grant the
  # private path because that's what Seatbelt sees after resolution.
  "/private/var/db/mds",

  # Timezone resolution. ICU (Node, Bun, Swift), CoreFoundation,
  # Python's datetime, Go's time package, and libc's tzset all
  # consult these on first call. Touched by essentially every
  # language runtime, so universally inert when granted.
  "/usr/share/zoneinfo",
  "/private/etc/localtime",
  "/private/var/db/timezone",
]

exec = [
  # POSIX sh and Bourne-family shells, stock-system locations only.
  # Third-party shells (Homebrew bash/zsh, Nix profiles, etc.)
  # belong in their respective installer's module — system/homebrew
  # covers the brewed copies.
  "/bin/sh",
  "/bin/bash",
  "/usr/bin/bash",
  "/bin/zsh",
  "/usr/bin/zsh",
  "/bin/dash",
  "/usr/bin/dash",
  # The env helper most shebangs go through.
  "/usr/bin/env",
  # macOS IO Registry probe — Bun (claude's runtime) shells out to
  # this at startup for hardware fingerprinting (battery, model,
  # serial). Inert on Linux (path doesn't exist).
  "/usr/sbin/ioreg",
]
