package profiles

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedAgentsContainExpectedProfiles(t *testing.T) {
	want := []string{"agents/coding.hcl", "agents/planning.hcl", "agents/reviewing.hcl"}
	for _, name := range want {
		data, err := fs.ReadFile(EmbeddedAgents, name)
		if err != nil {
			t.Errorf("missing embedded agent profile %q: %v", name, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("embedded agent profile %q is empty", name)
		}
	}
}

func TestEmbeddedAgentsHasNoUnexpectedFiles(t *testing.T) {
	allowed := map[string]bool{
		"agents/coding.hcl":    true,
		"agents/planning.hcl":  true,
		"agents/reviewing.hcl": true,
	}
	err := fs.WalkDir(EmbeddedAgents, "agents", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !allowed[path] && !strings.HasSuffix(path, ".gitkeep") {
			t.Errorf("unexpected embedded file: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
}
