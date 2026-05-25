# coding agent — general-purpose AI coding assistant (FR7.1).
# Requests read-write filesystem (broad "/" write) and unrestricted
# network (bare-wildcard domain). Both modes are inferred from these
# declarations — no separate filesystem/network_mode attributes.
agent "coding" {
  description = "General-purpose AI coding assistant"
  write       = ["/"]
  network {
    domain "*" {}
  }
}
