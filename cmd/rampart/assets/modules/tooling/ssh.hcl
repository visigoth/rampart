# tooling/ssh — OpenSSH client family (ssh, scp, sftp, ssh-add, ssh-keygen,
# ssh-keyscan, ssh-agent) with read access to ~/.ssh and /etc/ssh, write
# access to known_hosts and a conventional ControlMaster socket directory.
#
# Compose this with profile-specific network rules: rampart's forward
# proxy is HTTP-only and does NOT see SSH traffic — ssh makes raw TCP
# to port 22 (or whatever ssh_config specifies). To allow ssh to a
# given host, that host MUST appear in the profile's `allowed_domains`
# or `network { domain "..." }` block; the Seatbelt sandbox emits
# (remote tcp "<host>:*") which is enforced at connect time.
#
# ControlMaster sockets:
#   OpenSSH has no default ControlPath. The convention this module
#   adopts is ~/.ssh/cm/<hash>.sock (a dedicated subdirectory that
#   keeps sockets out of the keys+config area). To use it, add to
#   ssh_config:
#     Host *
#       ControlMaster auto
#       ControlPath  ~/.ssh/cm/%C
#       ControlPersist 5m
#   Profiles using a different ControlPath should pass
#   `control_master_dir = "<their-path>"` to this `use` block, or add
#   the path to the profile's own `write` list.

variable "ssh_dir" {
  type        = string
  default     = "~/.ssh"
  description = "User-level SSH config + key + known_hosts directory."
}

variable "control_master_dir" {
  type        = string
  default     = "~/.ssh/cm"
  description = "Convention dir for ControlMaster sockets. Profile-level override expected when ssh_config uses a different ControlPath."
}

# Read: the whole ~/.ssh tree (config, keys, known_hosts) and the
# system-wide /etc/ssh tree (ssh_config drop-ins, moduli, ca cert
# bundles, ssh_known_hosts).
read = [
  "${var.ssh_dir}",
  "/etc/ssh",
]

# Write: known_hosts (so ssh can append new host fingerprints when
# StrictHostKeyChecking=accept-new or =ask) and the ControlMaster
# socket dir. ssh-keygen also writes private keys under ~/.ssh — that
# intentionally is NOT covered here; agents that need to mint new
# keys should grant ${var.ssh_dir} write at the profile layer.
write = [
  "${var.ssh_dir}/known_hosts",
  "${var.control_master_dir}",
]

# ControlMaster sockets are Unix-domain listeners; Seatbelt
# distinguishes bind/connect on AF_UNIX from file-write/file-read on
# the socket inode, so we also need network-bind + network-outbound
# allow rules on the cm dir. The unix_sockets emit uses (subpath X)
# so it covers the temp names ssh creates during atomic rename
# (cm/<user>@<host>:<port>.<random>).
unix_sockets = [
  "${var.control_master_dir}",
]

exec = [
  # System install (macOS + most Linux distros).
  "/usr/bin/ssh",
  "/usr/bin/scp",
  "/usr/bin/sftp",
  "/usr/bin/ssh-add",
  "/usr/bin/ssh-keygen",
  "/usr/bin/ssh-keyscan",
  "/usr/bin/ssh-agent",
  # Homebrew openssh on Apple Silicon. The Cellar subpath catches the
  # versioned bin/ that /opt/homebrew/bin/ssh symlinks into.
  "/opt/homebrew/bin/ssh",
  "/opt/homebrew/bin/scp",
  "/opt/homebrew/bin/sftp",
  "/opt/homebrew/bin/ssh-add",
  "/opt/homebrew/bin/ssh-keygen",
  "/opt/homebrew/bin/ssh-keyscan",
  "/opt/homebrew/bin/ssh-agent",
  "/opt/homebrew/Cellar/openssh",
  # Intel Homebrew + the conventional Linux manual-install location.
  "/usr/local/bin/ssh",
  "/usr/local/bin/scp",
  "/usr/local/bin/sftp",
  "/usr/local/bin/ssh-add",
  "/usr/local/bin/ssh-keygen",
  "/usr/local/bin/ssh-keyscan",
  "/usr/local/bin/ssh-agent",
  "/usr/local/Cellar/openssh",
  # Linuxbrew.
  "/home/linuxbrew/.linuxbrew/bin/ssh",
  "/home/linuxbrew/.linuxbrew/bin/scp",
  "/home/linuxbrew/.linuxbrew/bin/sftp",
  "/home/linuxbrew/.linuxbrew/bin/ssh-add",
  "/home/linuxbrew/.linuxbrew/bin/ssh-keygen",
  "/home/linuxbrew/.linuxbrew/bin/ssh-keyscan",
  "/home/linuxbrew/.linuxbrew/bin/ssh-agent",
  "/home/linuxbrew/.linuxbrew/Cellar/openssh",
]
