# coding agent — general-purpose AI coding assistant (FR7.1).
# Requests read-write filesystem access, full network, and common toolchains.
agent "coding" {
  description  = "General-purpose AI coding assistant"
  filesystem   = "read-write"
  network_mode = "full"
  toolchains   = ["go", "node", "python", "rust"]
}
