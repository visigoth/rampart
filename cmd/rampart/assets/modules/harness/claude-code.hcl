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

variable "claude_cache_dir" {
  type        = string
  default     = "~/Library/Caches/claude-cli-nodejs"
  description = "Claude Code's per-project NodeJS cache + MCP logs dir (macOS)."
}

# Claude reads + writes several locations:
#   - ${var.claude_dir}: settings, sessions, .credentials.json, projects/,
#     todos/, file-history/, hooks/, plugins/, skills/, etc.
#   - ~/.claude.json: top-level config file (sibling of ~/.claude/, NOT
#     inside it). Claude updates this on nearly every startup; without
#     write access it spins in a lock-retry loop and never renders.
#   - ~/.claude.json.lock / ~/.claude.json.tmp.*: atomic-rename machinery
#     for the file above (lock file + temp file with PID suffix). The
#     glob covers the rotating .tmp.<pid>.<ts> names.
#   - ${var.claude_cache_dir}: NodeJS + MCP log spool.
read = [
  # macOS BSD syslog client socket. Bun (claude's runtime) calls
  # asl_open()/syslog() at JavaScriptCore bootstrap, which stats this
  # socket path before connect(2). The connect itself is sandboxed at
  # the unix-socket layer; this entry just covers the initial stat
  # that would otherwise emit an escalation per process start.
  # Not in system/base because non-Bun runtimes (Node, Go, Python,
  # plain shell) don't probe this path.
  "/private/var/run/syslog",
]

write = [
  "${var.claude_dir}",
  "~/.claude.json",
  "~/.claude.json.lock",
  "${var.claude_cache_dir}",
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
  # User-installed hooks. Claude's SessionStart/UserPromptSubmit/Stop
  # hooks all spawn scripts from these trees (peon-ping/peon.sh,
  # plugin run-hook.cmd, custom user hooks). Without exec here, every
  # session prints a noisy "Failed with non-blocking status code" for
  # each hook. Tradeoff: this is a user-writable area, so anything that
  # lands here can be executed — the agent must already trust whatever
  # is installed in ~/.claude.
  "~/.claude/hooks",
  "~/.claude/plugins",
]
