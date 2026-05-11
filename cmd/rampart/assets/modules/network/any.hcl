# network/any — wildcard ACL admitting any host on any path for the
# common HTTP methods AND any raw-TCP outbound (ssh, db, redis, etc.).
#
# This is a "filtered" mode policy (proxy stays in the path) rather
# than a "full" opt-out. The proxy still runs and logs every HTTP/
# HTTPS request; it just doesn't reject any of them. To skip the
# proxy entirely on darwin, see the network_mode resolution in
# policy.org.
#
# Two layers, because HTTP and non-HTTP take different paths through
# rampart's enforcement:
#
#   network { domain "**" { ... } }  — proxy-layer ACL. Matches via
#     rampart's DNS-segment matcher: "**" = zero-or-more labels. This
#     governs what the HTTP forward proxy admits.
#
#   allowed_domains = ["*"]          — sandbox-layer outbound ACL.
#     The macOS Seatbelt template emits (remote tcp "<entry>:*") per
#     allowed_domains entry; Seatbelt's host syntax accepts "*" as
#     any host. Without this, ssh / git over ssh / db client / etc.
#     hit a sandbox deny on TCP connect because the HTTP proxy can't
#     see them and there's no kernel-level allow rule. The "*" here
#     is the SBPL wildcard, NOT the rampart segment wildcard.
allowed_domains = ["*"]

network {
  domain "**" {
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
