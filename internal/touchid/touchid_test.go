package touchid

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// stubEvaluator is a controllable Evaluator for testing. canEval governs
// CanEvaluate's first return; approve / deny govern Evaluate. Set evalDelay
// to simulate a slow biometric prompt.
type stubEvaluator struct {
	canEval     bool
	canEvalErr  int
	approve     bool
	evalErrCode int
	evalDelay   time.Duration

	canCalls    atomic.Int32
	evalCalls   atomic.Int32
	lastReason  atomic.Value // string
}

func (s *stubEvaluator) CanEvaluate() (bool, int) {
	s.canCalls.Add(1)
	return s.canEval, s.canEvalErr
}

func (s *stubEvaluator) Evaluate(reason string) (bool, int) {
	s.evalCalls.Add(1)
	s.lastReason.Store(reason)
	if s.evalDelay > 0 {
		time.Sleep(s.evalDelay)
	}
	return s.approve, s.evalErrCode
}

func TestChannel_NilEvaluator_AlwaysDefer(t *testing.T) {
	c := &Channel{eval: nil}
	if c.Available() {
		t.Error("Available with nil eval should be false")
	}
	if got := c.Prompt(context.Background(), "test"); got != ResultDefer {
		t.Errorf("Prompt: got %v, want defer", got)
	}
}

func TestChannel_NilReceiver_AlwaysDefer(t *testing.T) {
	var c *Channel
	if c.Available() {
		t.Error("Available on nil receiver should be false")
	}
	if got := c.Prompt(context.Background(), "test"); got != ResultDefer {
		t.Errorf("Prompt on nil receiver: got %v, want defer", got)
	}
}

func TestChannel_HardwareUnavailable_Defer(t *testing.T) {
	eval := &stubEvaluator{canEval: false, canEvalErr: -6 /* LAErrorBiometryNotAvailable */}
	c := NewChannelWith(eval)

	if c.Available() {
		t.Error("Available should be false when CanEvaluate returns false")
	}
	if got := c.Prompt(context.Background(), "test"); got != ResultDefer {
		t.Errorf("Prompt with unavailable hardware: got %v, want defer", got)
	}
	if eval.evalCalls.Load() != 0 {
		t.Errorf("Evaluate should not be called when hardware unavailable; got %d calls", eval.evalCalls.Load())
	}
}

func TestChannel_NotEnrolled_Defer(t *testing.T) {
	// LAErrorBiometryNotEnrolled = -7
	eval := &stubEvaluator{canEval: false, canEvalErr: -7}
	c := NewChannelWith(eval)
	if got := c.Prompt(context.Background(), "test"); got != ResultDefer {
		t.Errorf("Prompt with not-enrolled: got %v, want defer", got)
	}
}

func TestChannel_UserApproves_Approve(t *testing.T) {
	eval := &stubEvaluator{canEval: true, approve: true}
	c := NewChannelWith(eval)
	if !c.Available() {
		t.Error("Available should be true when CanEvaluate returns true")
	}
	got := c.Prompt(context.Background(), "Rampart: allow read /etc/ssh")
	if got != ResultApprove {
		t.Errorf("Prompt: got %v, want approve", got)
	}
	if eval.evalCalls.Load() != 1 {
		t.Errorf("Evaluate should be called once; got %d", eval.evalCalls.Load())
	}
	if r, _ := eval.lastReason.Load().(string); r != "Rampart: allow read /etc/ssh" {
		t.Errorf("reason passed to LAContext: got %q", r)
	}
}

func TestChannel_UserCancels_Deny(t *testing.T) {
	// LAErrorUserCancel = -2
	eval := &stubEvaluator{canEval: true, approve: false, evalErrCode: -2}
	c := NewChannelWith(eval)
	if got := c.Prompt(context.Background(), "test"); got != ResultDeny {
		t.Errorf("Prompt on user cancel: got %v, want deny", got)
	}
}

func TestChannel_AuthenticationFailed_Deny(t *testing.T) {
	// LAErrorAuthenticationFailed = -1 (e.g. wrong finger N times in a row)
	eval := &stubEvaluator{canEval: true, approve: false, evalErrCode: -1}
	c := NewChannelWith(eval)
	if got := c.Prompt(context.Background(), "test"); got != ResultDeny {
		t.Errorf("Prompt on auth failed: got %v, want deny", got)
	}
}

func TestChannel_ContextCancelled_Defer(t *testing.T) {
	// Slow prompt so context cancellation wins the race.
	eval := &stubEvaluator{canEval: true, approve: true, evalDelay: 500 * time.Millisecond}
	c := NewChannelWith(eval)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	got := c.Prompt(ctx, "test")
	elapsed := time.Since(start)

	if got != ResultDefer {
		t.Errorf("Prompt with cancelled ctx: got %v, want defer", got)
	}
	// We should return promptly after cancellation, not wait for the slow
	// evaluator.
	if elapsed > 200*time.Millisecond {
		t.Errorf("Prompt took %v after cancel; should return promptly", elapsed)
	}
}

func TestChannel_ContextAlreadyDone_Defer(t *testing.T) {
	eval := &stubEvaluator{canEval: true, approve: true}
	c := NewChannelWith(eval)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done

	got := c.Prompt(ctx, "test")
	if got != ResultDefer {
		t.Errorf("Prompt with done ctx: got %v, want defer", got)
	}
}

func TestResult_String(t *testing.T) {
	tests := []struct {
		r    Result
		want string
	}{
		{ResultApprove, "approve"},
		{ResultDeny, "deny"},
		{ResultDefer, "defer"},
		{Result(99), "defer"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("Result(%d).String() = %q, want %q", int(tt.r), got, tt.want)
		}
	}
}

// TestNewChannel_ProductionConstructor smoke-checks that NewChannel returns a
// non-nil Channel on every platform. On darwin the underlying evaluator is
// LAContext-backed and we don't call Prompt (which would pop a real dialog);
// on other platforms the evaluator is nil and Available is false.
func TestNewChannel_ProductionConstructor(t *testing.T) {
	c := NewChannel()
	if c == nil {
		t.Fatal("NewChannel returned nil")
	}
	// Don't call Prompt — on darwin it would actually trigger biometrics.
}
