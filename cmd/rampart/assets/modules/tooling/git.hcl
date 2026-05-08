# tooling/git — git binary + ssh keys read + .gitconfig. No network.
#
# Network access for github.com / gitlab.com / etc. is intentionally not
# included here — many users need SSH-based git access (which doesn't go
# through the rampart proxy) and bundling network rules would
# misrepresent what git actually does.

read = [
  ".git",
  ".gitconfig",
  ".gitignore",
  ".gitmodules",
  ".ssh/known_hosts",
  ".ssh/config",
  ".ssh/id_ed25519.pub",
  ".ssh/id_rsa.pub",
]

exec = [
  "/usr/bin/git",
  "/usr/local/bin/git",
  "/usr/libexec/git-core",
]

write = [
  ".git",
]
