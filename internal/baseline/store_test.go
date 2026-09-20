package baseline

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStoreResolve(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "stig", "rhel9", "v2r9", "manifest.yaml")
	writeTestFile(t, manifestPath, validManifestYAML())
	store := NewStore(root)

	resolved, err := store.Resolve("rhel9:v2r9")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resolved.Ref != "rhel9:v2r9" || resolved.Path != filepath.Dir(manifestPath) {
		t.Fatalf("Resolve() = %#v", resolved)
	}

	if _, err := store.Resolve("rhel9"); err == nil || !strings.Contains(err.Error(), "expected <product>:<release>") {
		t.Fatalf("invalid ref error = %v", err)
	}
	if _, err := store.Resolve("rhel9:missing"); err == nil || !strings.Contains(err.Error(), "read manifest") {
		t.Fatalf("missing manifest error = %v", err)
	}
}

func TestStoreListSorted(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "stig", "zeta", "v2", "manifest.yaml"), validManifestYAML())
	writeTestFile(t, filepath.Join(root, "stig", "alpha", "v1", "manifest.yaml"), validManifestYAML())

	items, err := NewStore(root).List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	got := []string{items[0].Ref, items[1].Ref}
	want := []string{"alpha:v1", "zeta:v2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List() refs = %v, want %v", got, want)
	}
}

func TestResolvedRemediationFiles(t *testing.T) {
	path := t.TempDir()
	remediationDir := filepath.Join(path, "remediation")
	for _, name := range []string{"20-late.yaml", "00-first.yaml", "1-ignore.yaml", "aa-ignore.yaml", "10-ignore.txt"} {
		writeTestFile(t, filepath.Join(remediationDir, name), "stages: {}\n")
	}
	resolved := Resolved{Path: path}

	files, err := resolved.RemediationFiles()
	if err != nil {
		t.Fatalf("RemediationFiles() error = %v", err)
	}
	want := []string{filepath.Join(remediationDir, "00-first.yaml"), filepath.Join(remediationDir, "20-late.yaml")}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("RemediationFiles() = %v, want %v", files, want)
	}

	empty := Resolved{Path: t.TempDir()}
	if _, err := empty.RemediationFiles(); err == nil || !strings.Contains(err.Error(), "no remediation files") {
		t.Fatalf("empty RemediationFiles() error = %v", err)
	}
}

func TestResolvedGossFile(t *testing.T) {
	path := t.TempDir()
	resolved := Resolved{Path: path}
	gossPath := filepath.Join(path, "validation", "goss.yaml")
	writeTestFile(t, gossPath, "command: {}\n")

	got, err := resolved.GossFile()
	if err != nil || got != gossPath {
		t.Fatalf("GossFile() = %q, %v", got, err)
	}
	if err := os.Remove(gossPath); err != nil {
		t.Fatal(err)
	}
	if _, err := resolved.GossFile(); err == nil || !strings.Contains(err.Error(), "goss validation file") {
		t.Fatalf("missing GossFile() error = %v", err)
	}
}

func TestResolvedXCCDFFile(t *testing.T) {
	path := t.TempDir()
	resolved := Resolved{Path: path}
	if _, err := resolved.XCCDFFile(); err == nil || !strings.Contains(err.Error(), "no XCCDF source XML") {
		t.Fatalf("empty XCCDFFile() error = %v", err)
	}

	first := filepath.Join(path, "source", "a.xml")
	second := filepath.Join(path, "source", "z.xml")
	writeTestFile(t, second, "<Benchmark/>")
	writeTestFile(t, first, "<Benchmark/>")
	got, err := resolved.XCCDFFile()
	if err != nil || got != first {
		t.Fatalf("XCCDFFile() = %q, %v, want %q", got, err, first)
	}
}

func TestResolvedCKLBTemplateFile(t *testing.T) {
	path := t.TempDir()
	resolved := Resolved{Path: path}
	got, err := resolved.CKLBTemplateFile()
	if err != nil || got != "" {
		t.Fatalf("empty CKLBTemplateFile() = %q, %v", got, err)
	}

	first := filepath.Join(path, "source", "template.cklb")
	writeTestFile(t, first, "{}")
	got, err = resolved.CKLBTemplateFile()
	if err != nil || got != first {
		t.Fatalf("CKLBTemplateFile() = %q, %v", got, err)
	}

	writeTestFile(t, filepath.Join(path, "source", "second.cklb"), "{}")
	if _, err := resolved.CKLBTemplateFile(); err == nil || !strings.Contains(err.Error(), "multiple CKLB templates") {
		t.Fatalf("multiple CKLBTemplateFile() error = %v", err)
	}
}

func TestLoadManifest(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "valid", content: validManifestYAML()},
		{name: "invalid YAML", content: "schema_version: [", wantErr: "parse manifest"},
		{name: "missing schema", content: strings.Replace(validManifestYAML(), "schema_version: 1\n", "", 1), wantErr: "schema_version is required"},
		{name: "missing profile", content: strings.Replace(validManifestYAML(), "  id: test\n", "  id: \"\"\n", 1), wantErr: "profile.id is required"},
		{name: "missing OS", content: strings.Replace(validManifestYAML(), "  family: rhel\n", "  family: \"\"\n", 1), wantErr: "os family and major_version are required"},
		{name: "missing baseline", content: strings.Replace(validManifestYAML(), "  authority: DISA\n", "  authority: \"\"\n", 1), wantErr: "baseline authority, version, and release are required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.yaml")
			writeTestFile(t, path, tt.content)
			manifest, err := LoadManifest(path)
			if tt.wantErr == "" {
				if err != nil || manifest.Profile.ID != "test" {
					t.Fatalf("LoadManifest() = %#v, %v", manifest, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("LoadManifest() error = %v, want %q", err, tt.wantErr)
			}
		})
	}

	if _, err := LoadManifest(filepath.Join(t.TempDir(), "missing.yaml")); err == nil || !strings.Contains(err.Error(), "read manifest") {
		t.Fatalf("missing LoadManifest() error = %v", err)
	}
}

func validManifestYAML() string {
	return `schema_version: 1
profile:
  id: test
os:
  family: rhel
  major_version: 9
baseline:
  authority: DISA
  version: 2
  release: 9
`
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
