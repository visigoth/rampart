# lang/python — Python virtualenv + system Python + pypi package fetch.

variable "venv" {
  type        = string
  default     = ".venv"
  description = "Path to the project virtualenv (relative or absolute)."
}

read = [
  "/usr/lib/python3",
  "/usr/lib/python3.10",
  "/usr/lib/python3.11",
  "/usr/lib/python3.12",
  "/usr/lib/python3.13",
  "/usr/local/lib/python3",
]

exec = [
  "/usr/bin/python3",
  "/usr/local/bin/python3",
  "${var.venv}/bin/python",
  "${var.venv}/bin/pip",
]

write = [
  "${var.venv}",
]

network {
  domain "pypi.org" {
    allow "GET" {
      paths = ["/simple/**", "/pypi/**"]
    }
  }
  domain "files.pythonhosted.org" {
    allow "GET" {
      paths = ["/**"]
    }
  }
}
