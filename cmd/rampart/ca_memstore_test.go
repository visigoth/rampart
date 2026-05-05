package main

import (
	"errors"
	"testing"

	"github.com/visigoth/rampart/internal/ca"
)

// useMemCAStore swaps the ca package's storage operations for an in-memory
// stub for the duration of the test. It avoids the platform store entirely —
// no Keychain prompt on darwin, no ~/.config/rampart writes on linux — so
// tests that exercise the init flow run on any environment without the
// keychain-access-groups entitlement.
//
// The stub only covers the init path (Save / IsInstalled / Remove). LoadCA
// returns an error because constructing a usable *ca.CA from outside the
// ca package isn't possible (its tlsCert field is unexported). Tests that
// need LoadCA must use the real platform store.
func useMemCAStore(t *testing.T) {
	t.Helper()

	var installed bool

	origSave, origLoad, origIsInstalled, origRemove := ca.SaveCA, ca.LoadCA, ca.IsInstalled, ca.RemoveCA

	ca.SaveCA = func(_, _ []byte) error { installed = true; return nil }
	ca.IsInstalled = func() (bool, error) { return installed, nil }
	ca.RemoveCA = func() error { installed = false; return nil }
	ca.LoadCA = func() (*ca.CA, error) {
		return nil, errors.New("memstore: LoadCA not supported in tests (use real store)")
	}

	t.Cleanup(func() {
		ca.SaveCA = origSave
		ca.LoadCA = origLoad
		ca.IsInstalled = origIsInstalled
		ca.RemoveCA = origRemove
	})
}
