package remote

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Exonical/stigctl/internal/inventory"
)

type fakeRunner struct {
	artifact      []byte
	scanErr       error
	cleanupErr    error
	cancel        context.CancelFunc
	cleanupCalled bool
	cleanupCtxErr error
}

func (f *fakeRunner) Run(ctx context.Context, name string, args []string, stdout, _ *bytes.Buffer) error {
	last := args[len(args)-1]
	if name == "ssh" && strings.Contains(last, "mktemp -d") {
		stdout.WriteString("/var/tmp/stigctl-remote.abc123\n")
		return nil
	}
	if name == "ssh" && strings.Contains(last, "rm -rf --") {
		f.cleanupCalled = true
		f.cleanupCtxErr = ctx.Err()
		return f.cleanupErr
	}
	if name == "ssh" {
		if f.cancel != nil {
			f.cancel()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return f.scanErr
	}
	if name == "scp" && !strings.Contains(last, ":/var/tmp/") {
		if err := ctx.Err(); err != nil {
			return err
		}
		return os.WriteFile(last, f.artifact, 0o600)
	}
	return nil
}

func scanRequest(outputDir string) ScanRequest {
	return ScanRequest{
		Baseline: "rhel9:v2r9", Format: "json", OutputDir: outputDir,
		Payload: "/controller/payload.tar.gz", Binary: "/controller/stigctl",
		Target: inventory.Target{Name: "node01", Address: "node01.example.test", User: "scanner", Port: 22, Profile: "server"},
	}
}

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

func TestScanCollectsArtifactAndCleansRemoteWorkspace(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{artifact: []byte(`{"status":"complete"}`)}
	scanner := Scanner{runner: runner}

	result, err := scanner.Scan(context.Background(), scanRequest(dir))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(result.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), `{"status":"complete"}`; got != want {
		t.Fatalf("artifact = %q, want %q", got, want)
	}
	if !result.Published {
		t.Fatal("result was not marked as published")
	}
	if !runner.cleanupCalled {
		t.Fatal("remote cleanup was not called")
	}
}

func TestScanCollectsJUnitXMLArtifact(t *testing.T) {
	dir := t.TempDir()
	req := scanRequest(dir)
	req.Format = "junit"
	runner := &fakeRunner{artifact: []byte(`<?xml version="1.0"?><testsuite name="rhel9:v2r9" tests="1"></testsuite>`)}
	scanner := Scanner{runner: runner}

	result, err := scanner.Scan(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(result.OutputPath, ".xml") {
		t.Fatalf("JUnit output path = %q, want .xml suffix", result.OutputPath)
	}
	if !result.Published {
		t.Fatal("JUnit result was not published")
	}
}

func TestScanPreservesPreviousArtifactWhenRemoteFailsBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	req := scanRequest(dir)
	path := filepath.Join(dir, "node01-rhel9-v2r9.json")
	previous := []byte(`{"status":"previous"}`)
	if err := os.WriteFile(path, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{scanErr: errors.New("remote scan failed")}
	scanner := Scanner{runner: runner}

	result, err := scanner.Scan(context.Background(), req)
	if err == nil {
		t.Fatal("expected scan error")
	}
	if result.Published {
		t.Fatal("preserved artifact was reported as newly published")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(previous) {
		t.Fatalf("previous artifact was replaced: %q", data)
	}
}

func TestScanPublishesValidArtifactBeforeReportingNonzeroExit(t *testing.T) {
	dir := t.TempDir()
	runner := &fakeRunner{
		artifact: []byte(`{"status":"open"}`),
		scanErr:  errors.New("findings present"),
	}
	scanner := Scanner{runner: runner}

	result, err := scanner.Scan(context.Background(), scanRequest(dir))
	if err == nil {
		t.Fatal("expected nonzero scan error")
	}
	data, readErr := os.ReadFile(result.OutputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got, want := string(data), `{"status":"open"}`; got != want {
		t.Fatalf("artifact = %q, want %q", got, want)
	}
}

func TestScanReturnsCleanupErrorAfterPublishingArtifact(t *testing.T) {
	dir := t.TempDir()
	cleanupErr := errors.New("cleanup failed")
	runner := &fakeRunner{artifact: []byte(`{"status":"complete"}`), cleanupErr: cleanupErr}
	scanner := Scanner{runner: runner}

	result, err := scanner.Scan(context.Background(), scanRequest(dir))
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("error = %v, want cleanup error", err)
	}
	if _, statErr := os.Stat(result.OutputPath); statErr != nil {
		t.Fatalf("published artifact missing: %v", statErr)
	}
}

func TestScanCleanupUsesDetachedContextAfterCancellation(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	runner := &fakeRunner{cancel: cancel}
	scanner := Scanner{runner: runner}

	_, err := scanner.Scan(ctx, scanRequest(dir))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if !runner.cleanupCalled {
		t.Fatal("remote cleanup was not called")
	}
	if runner.cleanupCtxErr != nil {
		t.Fatalf("cleanup received canceled context: %v", runner.cleanupCtxErr)
	}
}
