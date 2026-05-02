# planning agent — architectural planning and design (FR7.2).
# Requests read-only filesystem access and no network.
agent "planning" {
  description  = "Architectural planning and design (read-only, no network)"
  filesystem   = "read-only"
  network_mode = "none"
}
