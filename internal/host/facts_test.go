package host

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectReadsOSRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	data := []byte("ID=rocky\nIGNORED LINE\nVERSION_ID=\"9.6\"\nNAME=Rocky Linux\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	facts := detect(path)
	if facts.OSID != "rocky" || facts.Version != "9.6" {
		t.Fatalf("detect() = %#v", facts)
	}
	if facts.Hostname == "" {
		t.Fatal("detect() did not populate hostname")
	}
}

func TestDetectMissingFileReturnsHostname(t *testing.T) {
	hostname, _ := os.Hostname()
	facts := detect(filepath.Join(t.TempDir(), "missing"))
	if facts != (Facts{Hostname: hostname}) {
		t.Fatalf("detect() = %#v, want hostname only", facts)
	}
}
