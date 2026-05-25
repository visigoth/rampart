# reviewing agent — code review with context lookup (FR7.3).
# Read-only filesystem; no intrinsic network ask — profile decides.
agent "reviewing" {
  description = "Code review with limited network for context lookup"
  read        = ["/"]
}
