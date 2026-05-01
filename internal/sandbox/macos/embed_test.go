//go:build darwin

package macos

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedSBPLContainsBaseTemplate(t *testing.T) {
	data, err := fs.ReadFile(EmbeddedSBPL, "sbpl/base.sb.tmpl")
	if err != nil {
		t.Fatalf("missing embedded SBPL base template: %v", err)
	}
	if len(data) == 0 {
		t.Error("embedded SBPL base template is empty")
	}
}

func TestEmbeddedSBPLAllFilesAreTemplates(t *testing.T) {
	err := fs.WalkDir(EmbeddedSBPL, "sbpl", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".sb.tmpl") {
			t.Errorf("unexpected non-template file in embedded SBPL: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
}
