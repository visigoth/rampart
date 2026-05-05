package main

import (
	"os"
	"path/filepath"
	"testing"
)

// tmpSock returns a unix-socket path short enough to fit in macOS's 104-byte
// sun_path limit. t.TempDir() on darwin returns paths under /var/folders/...
// that, combined with a long test name, blow past the limit and yield
// "bind: invalid argument" / "connect: invalid argument" errors.
func tmpSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rmpt")
	if err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}
