// Package touchid provides the Touch ID authorization channel (FR45).
//
// Touch ID is a supplementary biometric confirmation channel for sensitive
// escalations. The cross-platform Channel struct here defines the public
// API; the actual binding to LocalAuthentication.framework lives in
// touchid_darwin.go (CGo). On non-darwin builds, NewChannel returns a
// Channel that always defers, satisfying FR45.2 (graceful fallback).
package touchid

import "context"

// Result reports the outcome of a Touch ID prompt.
type Result int

const (
	// ResultDefer means the channel cannot make a decision (hardware
	// unavailable, not enrolled, ctx cancelled, no GUI session). The caller
	// should fall through to other channels.
	ResultDefer Result = iota
	// ResultApprove means the user passed biometric authentication.
	ResultApprove
	// ResultDeny means the user explicitly cancelled or repeatedly failed
	// authentication. Distinct from ResultDefer because the user expressed
	// intent.
	ResultDeny
)

func (r Result) String() string {
	switch r {
	case ResultApprove:
		return "approve"
	case ResultDeny:
		return "deny"
	default:
		return "defer"
	}
}

// Evaluator abstracts LAContext so the Channel logic is testable without
// requiring real biometric hardware. CanEvaluate maps to
// -[LAContext canEvaluatePolicy:error:]; Evaluate maps to
// -[LAContext evaluatePolicy:localizedReason:reply:] (synchronous wrapper).
type Evaluator interface {
	// CanEvaluate reports whether the device can perform biometric
	// authentication right now (hardware present, user enrolled).
	// errCode is the underlying LAError code (0 on success).
	CanEvaluate() (available bool, errCode int)

	// Evaluate triggers the biometric prompt with the given localized reason
	// and blocks until the user authenticates, cancels, or fails.
	// approved is true iff the user succeeded; errCode is the LAError code.
	Evaluate(reason string) (approved bool, errCode int)
}

// Channel is a Touch ID authorization channel. Construct with NewChannel for
// a real LAContext-backed implementation, or NewChannelWith for tests.
type Channel struct {
	eval Evaluator
}

// NewChannelWith returns a Channel using the supplied Evaluator. Useful in
// tests; production callers should use NewChannel.
func NewChannelWith(eval Evaluator) *Channel {
	return &Channel{eval: eval}
}

// Available reports whether Touch ID can be presented to the user right now.
// Always false when the channel was constructed without an Evaluator (e.g.
// non-darwin builds) — see FR45.2.
func (c *Channel) Available() bool {
	if c == nil || c.eval == nil {
		return false
	}
	ok, _ := c.eval.CanEvaluate()
	return ok
}

// Prompt triggers a biometric prompt with the given localized reason
// (FR45.1). Returns ResultDefer when the channel is unavailable or ctx is
// cancelled before the user responds; ResultApprove or ResultDeny otherwise.
//
// The underlying LAContext.evaluatePolicy call cannot be cancelled from
// outside without invalidating the context, so when ctx fires we abandon
// the result. Subsequent calls construct a fresh Evaluator interaction.
func (c *Channel) Prompt(ctx context.Context, reason string) Result {
	if c == nil || c.eval == nil {
		return ResultDefer
	}
	if !c.Available() {
		return ResultDefer
	}

	type evalResult struct {
		approved bool
		errCode  int
	}
	ch := make(chan evalResult, 1)
	go func() {
		ok, code := c.eval.Evaluate(reason)
		ch <- evalResult{approved: ok, errCode: code}
	}()

	select {
	case r := <-ch:
		if r.approved {
			return ResultApprove
		}
		// User cancelled, fell back, or repeatedly failed — treat as Deny so
		// the engine doesn't leak the prompt to other channels (TR79).
		return ResultDeny
	case <-ctx.Done():
		return ResultDefer
	}
}
