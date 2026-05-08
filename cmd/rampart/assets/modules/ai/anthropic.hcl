# ai/anthropic — Anthropic API (Claude).

network {
  domain "api.anthropic.com" {
    allow "POST" {
      paths = ["/v1/messages", "/v1/complete", "/v1/messages/**"]
    }
    allow "GET" {
      paths = ["/v1/**"]
    }
  }
}
