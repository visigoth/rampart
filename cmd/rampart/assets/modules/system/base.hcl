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
]

exec = [
  # POSIX sh and Bourne-family shells.
  "/bin/sh",
  "/bin/bash",
  "/usr/bin/bash",
  "/bin/zsh",
  "/usr/bin/zsh",
  "/bin/dash",
  "/usr/bin/dash",
  # Homebrew + linuxbrew installs.
  "/opt/homebrew/bin/bash",
  "/opt/homebrew/bin/zsh",
  "/usr/local/bin/bash",
  "/usr/local/bin/zsh",
  "/home/linuxbrew/.linuxbrew/bin/bash",
  "/home/linuxbrew/.linuxbrew/bin/zsh",
  # The env helper most shebangs go through.
  "/usr/bin/env",
]
