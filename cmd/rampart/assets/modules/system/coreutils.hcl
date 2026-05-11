# system/coreutils — exec on the POSIX shell-script essentials.
#
# Hook scripts, build scripts, and plugin glue from claude-code,
# peon-ping, superpowers, etc. all assume these tools exist on PATH.
# Without them, even a trivial `dirname "$0"` shells out and gets EPERM
# from the sandbox.
#
# This module is intentionally limited to read-only / pure-function
# tools (text transforms, path manipulation, time/test predicates).
# Mutating tools (rm, mv, cp, mkdir, chmod, touch) live elsewhere so a
# profile can opt into "scripts can compute and inspect" without
# implicitly granting "scripts can modify the filesystem outside their
# write list".

exec = [
  # Path manipulation.
  "/usr/bin/dirname",
  "/usr/bin/basename",
  "/usr/bin/realpath",
  "/usr/bin/readlink",
  # Shebang dispatcher / env query.
  "/usr/bin/env",
  # Trivial primitives.
  "/bin/echo",
  "/usr/bin/echo",
  "/usr/bin/printf",
  "/usr/bin/sleep",
  "/usr/bin/true",
  "/usr/bin/false",
  "/usr/bin/test",
  "/bin/test",
  # NB: /bin/[ and /usr/bin/[ exist as aliases for /usr/bin/test but the
  # rampart glob validator treats `[` as an unsupported wildcard
  # character; scripts that need them invoke `test` instead, which is
  # POSIX-equivalent.
  "/usr/bin/expr",
  # Text transforms.
  "/usr/bin/awk",
  "/usr/bin/sed",
  "/usr/bin/sort",
  "/usr/bin/uniq",
  "/usr/bin/cut",
  "/usr/bin/tr",
  "/usr/bin/rev",
  "/usr/bin/xargs",
  "/usr/bin/tee",
  "/usr/bin/cmp",
  "/usr/bin/diff",
  "/usr/bin/od",
  "/usr/bin/strings",
  "/usr/bin/base64",
  # Time + dates + IDs.
  "/bin/date",
  "/usr/bin/date",
  "/usr/bin/stat",
  "/bin/stat",
  "/usr/bin/md5",
  "/usr/bin/shasum",
  "/usr/bin/sha256sum",
  "/usr/bin/sha1sum",
  "/usr/bin/uuidgen",
  # JSON + YAML inspection (commonly shipped via Homebrew but the user
  # often has the system version; if not, the path is inert).
  "/usr/local/bin/jq",
  "/opt/homebrew/bin/jq",
  "/usr/local/bin/yq",
  "/opt/homebrew/bin/yq",
]
