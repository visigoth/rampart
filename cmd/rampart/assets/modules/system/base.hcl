# system/base — read-only access to /etc essentials a typical CLI needs:
# DNS resolution, hostname lookup, user database, root CA bundle, timezone.
#
# This is the minimum needed for outbound HTTPS to resolve a name and
# verify a TLS certificate. Most language modules implicitly depend on it.

read = [
  "/etc/resolv.conf",
  "/etc/hosts",
  "/etc/passwd",
  "/etc/group",
  "/etc/nsswitch.conf",
  "/etc/localtime",
  "/etc/timezone",
  "/etc/ssl/certs",
  "/etc/ssl/cert.pem",
  "/etc/pki/tls/certs",
  "/usr/share/ca-certificates",
]
