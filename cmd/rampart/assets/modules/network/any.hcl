# network/any — wildcard ACL admitting any host on any path for the
# common HTTP methods.
#
# This is a "filtered" mode policy (proxy stays in the path) rather than
# a "full" opt-out. The proxy still runs and logs every request; it just
# doesn't reject any of them. To skip the proxy entirely on darwin, see
# the network_mode resolution in policy.org.

network {
  domain "*" {
    allow "GET" {
      paths = ["/**"]
    }
    allow "POST" {
      paths = ["/**"]
    }
    allow "PUT" {
      paths = ["/**"]
    }
    allow "PATCH" {
      paths = ["/**"]
    }
    allow "DELETE" {
      paths = ["/**"]
    }
    allow "HEAD" {
      paths = ["/**"]
    }
    allow "OPTIONS" {
      paths = ["/**"]
    }
  }
}
