package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil || !strings.Contains(err.Error(), "read rules") {
		t.Fatalf("missing Load() error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte("rules: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "parse rules") {
		t.Fatalf("invalid Load() error = %v", err)
	}
}
