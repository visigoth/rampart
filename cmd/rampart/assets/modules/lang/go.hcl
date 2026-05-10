# lang/go — Go toolchain + module proxy + checksum database.

read = [
  "/usr/local/go",
  "/usr/lib/go",
]

exec = [
  "/usr/local/go/bin/go",
  "/usr/local/go/bin/gofmt",
  "/usr/lib/go/bin/go",
  "/usr/lib/go/bin/gofmt",
]

write = [
  "go.mod",
  "go.sum",
  "~/go",
]

network {
  domain "proxy.golang.org" {
    allow "GET" {
      paths = ["/**"]
    }
  }
  domain "sum.golang.org" {
    allow "GET" {
      paths = ["/**"]
    }
  }
}
