# lang/node — Node + npm + the npm registry.

variable "node_modules" {
  type        = string
  default     = "node_modules"
  description = "Path to the project node_modules directory (relative or absolute)."
}

read = [
  "/usr/lib/node_modules",
  "/usr/local/lib/node_modules",
]

exec = [
  "/usr/bin/node",
  "/usr/local/bin/node",
  "/usr/bin/npm",
  "/usr/local/bin/npm",
  "/usr/bin/npx",
  "/usr/local/bin/npx",
]

write = [
  "${var.node_modules}",
  ".npm",
]

network {
  domain "registry.npmjs.org" {
    allow "GET" {
      paths = ["/**"]
    }
  }
  domain "*.npmjs.org" {
    allow "GET" {
      paths = ["/**"]
    }
  }
}
