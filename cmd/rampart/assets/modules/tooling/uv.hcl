# tooling/uv — Astral's uv package manager (Python).
#
# Covers uv's local cache, config dir, and the per-user lockfiles
# it maintains during sdist/wheel resolution. Claude Code shells
# out to `uv` (and `uvx`) for some hook script flows and for
# launching Python plugins; without these grants the first uv
# invocation hangs the agent on a single write escalation against
# the sdists cache's .git bookkeeping dir.
#
# uv itself ships via Homebrew on macOS (covered by
# system/homebrew) or the official installer on Linux. This module
# only deals with the runtime data dirs — it is intentionally
# narrow about NOT granting random sub-pip behaviour beyond uv's
# own cache surface.

variable "uv_cache_dir" {
  type        = string
  default     = "~/.cache/uv"
  description = "uv's source distribution + wheel cache."
}

variable "uv_data_dir" {
  type        = string
  default     = "~/.local/share/uv"
  description = "uv's persistent state (installed tools, tool-receipts)."
}

variable "uv_config_dir" {
  type        = string
  default     = "~/.config/uv"
  description = "uv's user config (uv.toml, pip.conf-equivalents)."
}

read = [
  "${var.uv_cache_dir}",
  "${var.uv_data_dir}",
  "${var.uv_config_dir}",
]

write = [
  "${var.uv_cache_dir}",
  "${var.uv_data_dir}",
]

network {
  # uv resolves packages from PyPI by default; covers Warehouse JSON
  # API + sdist/wheel downloads. files.pythonhosted.org is the CDN
  # that hosts the actual artifacts.
  domain "pypi.org" {
    allow "GET" { paths = ["/**"] }
  }
  domain "files.pythonhosted.org" {
    allow "GET" { paths = ["/**"] }
  }
  # uv's official binary distribution mirror (when self-updating).
  domain "astral.sh" {
    allow "GET" { paths = ["/**"] }
  }
}
