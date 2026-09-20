package profile

import (
	"os"
	"path/filepath"
	"strings"
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
	if _, err := NewStore(root).Resolve("missing"); err == nil || !strings.Contains(err.Error(), "profile \"missing\"") {
		t.Fatalf("missing Resolve() error = %v", err)
	}
}

func TestList(t *testing.T) {
	root := t.TempDir()
	profileDir := filepath.Join(root, "profiles")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for id, name := range map[string]string{"zeta": "Zeta", "alpha": "Alpha"} {
		data := []byte("schema_version: 1\nprofile:\n  id: " + id + "\n  name: " + name + "\n")
		if err := os.WriteFile(filepath.Join(profileDir, id+".yaml"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	profiles, err := NewStore(root).List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(profiles) != 2 || profiles[0].Profile.ID != "alpha" || profiles[1].Profile.ID != "zeta" {
		t.Fatalf("List() = %#v", profiles)
	}
}
