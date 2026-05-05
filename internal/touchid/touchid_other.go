//go:build !darwin

package touchid

// NewChannel returns a Channel that always defers on non-darwin platforms.
// LocalAuthentication is a macOS-only framework (FR45, AC13); on Linux the
// channel is unreachable and callers must rely on tmux pane / hook / remote.
func NewChannel() *Channel {
	return &Channel{eval: nil}
}
