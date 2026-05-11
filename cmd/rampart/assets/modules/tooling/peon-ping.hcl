# tooling/peon-ping — runtime support for the peon-ping Claude Code hook.
#
# peon-ping is the Warcraft III "peon" voice-line notification helper
# (https://github.com/openpeon/peon-ping) that Claude Code invokes on
# session lifecycle events: SessionStart, UserPromptSubmit, Stop, etc.
# The hook lives at ~/.claude/hooks/peon-ping/peon.sh as a symlink to
# /opt/homebrew/opt/peon-ping/libexec/peon.sh and shells out to several
# macOS audio + notification primitives.
#
# What the hook actually does (researched by reading
# /opt/homebrew/opt/peon-ping/libexec/peon.sh):
#   - calls system_profiler SPAudioDataType to detect headphones
#   - calls afplay to play .wav files from ${var.peon_packs_dir}
#   - calls osascript / terminal-notifier for Notification Center
#   - reads/writes state files in ~/.claude/hooks/peon-ping/.state.json
#     (covered by harness/claude-code's ${var.claude_dir} write)
#   - reaches the local "peon relay" daemon on localhost (covered by the
#     baseline loopback allow rule)
#
# Cross-platform: this module lists macOS and Linux install paths; the
# absent paths are silently ignored at sandbox compile time.

variable "peon_packs_dir" {
  type        = string
  default     = "~/.openpeon"
  description = "openpeon sound-pack directory (read-only at runtime)."
}

# The hook reads .wav files from ${peon_packs_dir}/packs/<pack>/sounds/.
# Granted via read so write access isn't broadened unnecessarily.
read = [
  "${var.peon_packs_dir}",
]

exec = [
  # peon-ping bundled scripts (peon.sh, notify.sh, relay.sh, ...).
  # The user's hook entry at ~/.claude/hooks/peon-ping/peon.sh is a
  # symlink into this libexec — Seatbelt checks the realpath after
  # symlink resolution, so we allow the realpath subpath.
  "/opt/homebrew/opt/peon-ping",
  "/opt/homebrew/Cellar/peon-ping",
  "/usr/local/opt/peon-ping",
  "/usr/local/Cellar/peon-ping",
  "/home/linuxbrew/.linuxbrew/opt/peon-ping",
  "/home/linuxbrew/.linuxbrew/Cellar/peon-ping",
  # macOS audio playback.
  "/usr/bin/afplay",
  # macOS audio-device introspection (used to detect headphones vs
  # built-in speakers so the hook can choose volume).
  "/usr/sbin/system_profiler",
  # macOS native notifications. osascript is system-installed; the
  # terminal-notifier CLI is a separate Homebrew install used as the
  # preferred path when present.
  "/usr/bin/osascript",
  "/usr/local/bin/terminal-notifier",
  "/opt/homebrew/bin/terminal-notifier",
  # Linux audio + notify alternatives (best-effort; the hook auto-
  # detects which is available).
  "/usr/bin/aplay",
  "/usr/bin/paplay",
  "/usr/bin/notify-send",
]
