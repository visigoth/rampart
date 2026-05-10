# harness/claude-code — runtime support for Anthropic's Claude Code CLI.
#
# Cross-platform. Pair with `ai/anthropic` for API network access; this
# module covers only the local runtime surface (binary paths, the config
# directory, and platform-specific credential helpers).
#
# Credential storage:
#   - macOS: claude-code reads its stored token via /usr/bin/security
#     (the macOS Keychain CLI). The exec entry below grants this; without
#     it the agent crashes at startup with "EPERM ... posix_spawn 'security'".
#   - Linux: claude-code stores credentials at ~/.claude/.credentials.json
#     directly. /usr/bin/security is absent on Linux and the rule for it
#     is silently ignored at sandbox compile time.

variable "claude_dir" {
  type        = string
  default     = "~/.claude"
  description = "Claude Code's config + sessions + credentials dir."
}

# ~/.claude tree: settings, sessions, .credentials.json, projects/,
# todos/, file-history/, hooks/, plugins/, skills/, etc. Write implies
# read at the capability level (FR1.12), so this also covers reads.
write = [
  "${var.claude_dir}",
]

exec = [
  # Claude binary — Homebrew Cask on Apple Silicon. The symlink under
  # bin/ resolves into Caskroom/<version>/, so both are listed: the
  # subpath rule against Caskroom covers any installed version.
  "/opt/homebrew/bin/claude",
  "/opt/homebrew/Caskroom/claude-code",
  # Claude binary — Homebrew Cask (Intel) and the default install dir
  # for Linux package managers and manual installs (deb/rpm/tarball).
  "/usr/local/bin/claude",
  "/usr/local/Caskroom/claude-code",
  # Claude binary — Linuxbrew default location.
  "/home/linuxbrew/.linuxbrew/bin/claude",
  "/home/linuxbrew/.linuxbrew/Caskroom/claude-code",
  # macOS Keychain CLI — claude-code spawns this to read/write the
  # stored API token. Absent on Linux; rule is inert there.
  "/usr/bin/security",
]
