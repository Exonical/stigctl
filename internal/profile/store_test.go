package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolve(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "profiles"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte("schema_version: 1\nprofile:\n  id: server\n  name: Server\n")
	if err := os.WriteFile(filepath.Join(root, "profiles", "server.yaml"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := NewStore(root).Resolve("server")
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile.Name != "Server" {
		t.Fatalf("Name = %q", got.Profile.Name)
	}
}
