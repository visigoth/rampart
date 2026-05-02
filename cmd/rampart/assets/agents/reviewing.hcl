# reviewing agent — code review with context lookup (FR7.3).
# Requests read-only filesystem and limited network for fetching external context.
agent "reviewing" {
  description  = "Code review with limited network for context lookup"
  filesystem   = "read-only"
  network_mode = "filtered"
}
