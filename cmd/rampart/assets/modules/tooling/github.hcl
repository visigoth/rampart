# tooling/github — GitHub CLI + HTTP API + raw / asset downloads.
#
# Distinct from tooling/git (local CLI / ssh keys). Combine both to grant
# `git fetch over HTTPS` plus `gh api` style flows.

read = [
  # `gh` config + auth state (host tokens, OAuth refresh).
  "~/.config/gh",
]

write = [
  # gh writes auth token + host config on first login / refresh.
  "~/.config/gh",
]

# `gh` itself is shipped via Homebrew under /opt/homebrew/Cellar/gh
# (Apple Silicon) or /usr/local/Cellar/gh (Intel). Grant the binary
# via system/homebrew rather than enumerating per-tool here.

network {
  domain "api.github.com" {
    allow "GET" {
      paths = ["/**"]
    }
    allow "POST" {
      paths = ["/**"]
    }
    allow "PATCH" {
      paths = ["/**"]
    }
  }
  domain "github.com" {
    allow "GET" {
      paths = ["/**"]
    }
    allow "POST" {
      paths = ["/**"]
    }
  }
  domain "*.githubusercontent.com" {
    allow "GET" {
      paths = ["/**"]
    }
  }
  domain "objects.githubusercontent.com" {
    allow "GET" {
      paths = ["/**"]
    }
  }
}
