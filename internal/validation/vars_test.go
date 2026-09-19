package validation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteVars(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vars.yaml")
	err := WriteVars(path, Vars{
		Profile:  "server",
		Hostname: "node01",
		EnabledRules: map[string]bool{
			"V-1": true,
			"V-2": false,
		},
	})
	if err != nil {
		t.Fatalf("WriteVars() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"profile: server", "hostname: node01", "V-1: true", "V-2: false"} {
		if !strings.Contains(text, want) {
			t.Fatalf("vars file missing %q:\n%s", want, text)
		}
	}
}
