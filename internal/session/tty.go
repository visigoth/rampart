package session

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal reports whether f is attached to a terminal using the TIOCGWINSZ
// ioctl (Linux/macOS). Returns false on any error, including non-terminals.
func isTerminal(f *os.File) bool {
	var ws [4]uint16
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TIOCGWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
	return errno == 0
}
