# tooling/github — GitHub HTTP API + raw / asset downloads.
#
# Distinct from tooling/git (local CLI / ssh keys). Combine both to grant
# `git fetch over HTTPS` plus `gh api` style flows.

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
