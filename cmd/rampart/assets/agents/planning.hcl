# planning agent — architectural planning and design (FR7.2).
# Read-only filesystem (broad "/" read; profile narrows). Filtered
# network — the agent doesn't enumerate domains, relying on the
# profile to authorise specific lookup targets. Modes are inferred
# from declarations.
agent "planning" {
  description = "Architectural planning and design (read-only, filtered network)"
  read        = ["/"]
  # No `network` block here — the agent has no intrinsic network ask.
  # Profile may grant filtered network for context lookup; an empty
  # network section here means the agent's contribution is "none",
  # which clamps the merged mode to none. To request filtered, list
  # at least one concrete domain (e.g. `domains = ["*.wikipedia.org"]`).
}
