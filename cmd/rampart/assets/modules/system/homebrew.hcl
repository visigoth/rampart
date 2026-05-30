# system/homebrew — broad exec + read on the Homebrew prefix.
#
# Homebrew installs all its formulae under a single prefix tree
# (Apple Silicon: /opt/homebrew; Intel macOS + Linuxbrew: /usr/local
# or /home/linuxbrew/.linuxbrew). Tools, shared libraries, formula
# scripts, config files, and version-pinned `Cellar/` payloads all
# live under this one root.
#
# When a profile uses this module it's declaring "I trust whatever
# the user has installed via brew." That's reasonable for personal
# development machines but should be considered for CI / locked-down
# deployments — formulae can ship arbitrary post-install scripts and
# the prefix is user-writable.
#
# With broad subpath grants here, individual tooling modules don't
# need to enumerate per-tool binary paths. `gh`, `direnv`, `jq`,
# `uvx`, GNU coreutils' `g*` aliases, and any other brewed binary
# resolve automatically. The pre-merge path canonicaliser emits
# both the /opt/homebrew/bin/<tool> symlink path AND its
# Cellar-versioned resolution, so subpath grants on /opt/homebrew
# cover any installed version transparently.

read = [
  # Apple Silicon Homebrew install root.
  "/opt/homebrew",
  # Intel Homebrew install root.
  "/usr/local",
  # Linuxbrew.
  "/home/linuxbrew/.linuxbrew",
]

exec = [
  # Mirror the read entries — every binary under these trees is
  # exec-able. Granted as subpaths so versioned Cellar/<formula>/
  # <version>/bin/<tool> targets resolve.
  "/opt/homebrew",
  "/usr/local",
  "/home/linuxbrew/.linuxbrew",
]
