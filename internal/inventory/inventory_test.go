package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMergesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	data := []byte(`version: 1
defaults:
  user: scanner
  port: 2222
  sudo: true
  profile: server
hosts:
  - name: node01
    address: 192.0.2.10
    hostname: node01.example.test
  - name: node02
    address: node02.example.test
    user: operator
    sudo: false
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets", len(targets))
	}
	if targets[0].User != "scanner" || targets[0].Port != 2222 || !targets[0].Sudo || targets[0].Profile != "server" {
		t.Fatalf("defaults not merged: %#v", targets[0])
	}
	if targets[1].User != "operator" || targets[1].Sudo {
		t.Fatalf("host overrides not merged: %#v", targets[1])
	}
}

func TestLoadRejectsDuplicateAndUnsafeNames(t *testing.T) {
	for name, input := range map[string]string{
		"duplicate": `version: 1
defaults: {user: scanner}
hosts:
  - {name: node01, address: node01}
  - {name: node01, address: node02}
`,
		"unsafe": `version: 1
defaults: {user: scanner}
hosts:
  - {name: ../node01, address: node01}
`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inventory.yaml")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("expected inventory validation error")
			}
		})
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.yaml")
	data := []byte(`version: 1
defaults: {user: scanner}
hosts:
  - {name: node01, address: node01, identitiy_file: /typo}
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}
