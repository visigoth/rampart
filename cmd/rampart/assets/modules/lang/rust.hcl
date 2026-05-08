# lang/rust — Cargo + crates.io.

variable "cargo_home" {
  type        = string
  default     = ".cargo"
  description = "Cargo's CARGO_HOME directory (writable cache + registry)."
}

read = [
  "/usr/lib/rustlib",
  "/usr/local/lib/rustlib",
]

exec = [
  "/usr/bin/cargo",
  "/usr/local/bin/cargo",
  "/usr/bin/rustc",
  "/usr/local/bin/rustc",
  "/usr/bin/rustup",
  "/usr/local/bin/rustup",
]

write = [
  "${var.cargo_home}",
  "target",
  "Cargo.lock",
]

network {
  domain "crates.io" {
    allow "GET" {
      paths = ["/**"]
    }
  }
  domain "static.crates.io" {
    allow "GET" {
      paths = ["/**"]
    }
  }
  domain "index.crates.io" {
    allow "GET" {
      paths = ["/**"]
    }
  }
}
