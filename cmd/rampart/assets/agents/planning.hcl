# planning agent — architectural planning and design (FR7.2).
# Requests read-only filesystem access and filtered network for context lookup.
agent "planning" {
  description  = "Architectural planning and design (read-only, filtered network)"
  filesystem   = "read-only"
  network_mode = "filtered"
}
