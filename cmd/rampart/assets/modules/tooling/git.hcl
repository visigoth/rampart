# tooling/git — git binary + ssh keys read + .gitconfig. No network.
#
# Network access for github.com / gitlab.com / etc. is intentionally not
# included here — many users need SSH-based git access (which doesn't go
# through the rampart proxy) and bundling network rules would
# misrepresent what git actually does.

read = [
  # Project-level (workdir-relative).
  ".git",
  ".gitignore",
  ".gitmodules",
  # User-level (HOME-relative).
  "~/.gitconfig",
  "~/.ssh/known_hosts",
  "~/.ssh/config",
  "~/.ssh/id_ed25519.pub",
  "~/.ssh/id_rsa.pub",
]

exec = [
  # macOS system git.
  "/usr/bin/git",
  "/usr/libexec/git-core",
  # Homebrew installs. The Caskroom-style subpath catches versioned dirs
  # so PATH lookup of /opt/homebrew/bin/git (a symlink into Cellar) works.
  "/opt/homebrew/bin/git",
  "/opt/homebrew/Cellar/git",
  "/opt/homebrew/libexec/git-core",
  # Linux distro + Linuxbrew + manual installs.
  "/usr/local/bin/git",
  "/usr/local/libexec/git-core",
  "/home/linuxbrew/.linuxbrew/bin/git",
  "/home/linuxbrew/.linuxbrew/Cellar/git",
]

write = [
  ".git",
]
