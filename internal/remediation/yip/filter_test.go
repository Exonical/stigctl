package yip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilterFilesRemovesExceptedStep(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "30-ssh.yaml")
	content := `name: SSH
stages:
  stig:
    - name: "V-1 - Disable root SSH"
      commands:
        - "true"
    - name: "V-2 - Keep this"
      commands:
        - "true"
`
	if err := os.WriteFile(source, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := FilterFiles([]string{source}, "stig", map[string]struct{}{
		"V-1 - Disable root SSH": {},
	})
	if err != nil {
		t.Fatalf("FilterFiles() error = %v", err)
	}
	defer result.Cleanup()

	if len(result.Files) != 1 {
		t.Fatalf("len(files) = %d", len(result.Files))
	}
	got, err := os.ReadFile(result.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if strings.Contains(text, "V-1 - Disable root SSH") {
		t.Fatal("excepted step remained in filtered Yip")
	}
	if !strings.Contains(text, "V-2 - Keep this") {
		t.Fatal("non-excepted step was removed")
	}
}
