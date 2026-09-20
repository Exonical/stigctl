package remote

import (
	"strings"
	"testing"

	"github.com/Exonical/stigctl/internal/inventory"
)

func TestBuildScanCommandUsesNonInteractiveSudoAndQuotesMetadata(t *testing.T) {
	req := ScanRequest{
		Baseline: "rhel9:v2r9",
		Format:   "cklb",
		Target: inventory.Target{
			Sudo: true, Profile: "server", Hostname: "node01", Comments: "owner's host",
		},
	}
	command := buildScanCommand(req, "/var/tmp/stigctl-remote.abc123", "/var/tmp/stigctl-remote.abc123/result.cklb")
	for _, expected := range []string{
		"sudo -n --", "'--content-root'", "'rhel9:v2r9'", "'--profile' 'server'",
		"'--target-comments' 'owner'\\''s host'",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("command does not contain %q:\n%s", expected, command)
		}
	}
}

func TestSSHArgsEnforceBatchAndHostKeyChecking(t *testing.T) {
	target := inventory.Target{Port: 2222, IdentityFile: "/keys/id", KnownHostsFile: "/keys/known_hosts"}
	got := strings.Join(sshArgs(target), " ")
	for _, expected := range []string{"BatchMode=yes", "StrictHostKeyChecking=yes", "-p 2222", "-i /keys/id", "IdentitiesOnly=yes", "UserKnownHostsFile=/keys/known_hosts"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("SSH args %q do not contain %q", got, expected)
		}
	}
}

func TestSCPDestinationBracketsIPv6(t *testing.T) {
	target := inventory.Target{User: "scanner", Address: "2001:db8::10"}
	if got, want := scpDestination(target, "/tmp/result"), "scanner@[2001:db8::10]:/tmp/result"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
