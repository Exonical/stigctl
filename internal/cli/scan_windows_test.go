//go:build windows

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Exonical/stigctl/internal/remote"
)

type windowsControllerScanner struct {
	payloadPath string
}

func (s *windowsControllerScanner) Scan(_ context.Context, req remote.ScanRequest) (remote.ScanResult, error) {
	binary, err := os.ReadFile(req.Binary)
	if err != nil {
		return remote.ScanResult{Target: req.Target}, fmt.Errorf("read staged binary: %w", err)
	}
	if string(binary) != "linux-stigctl" {
		return remote.ScanResult{Target: req.Target}, fmt.Errorf("unexpected staged binary %q", binary)
	}
	if !filepath.IsAbs(req.Binary) {
		return remote.ScanResult{Target: req.Target}, fmt.Errorf("remote binary path is not absolute: %q", req.Binary)
	}
	for _, required := range []string{
		"content/stig/rhel9/v2r9/manifest.yaml",
		"content/profiles/server.yaml",
	} {
		found, err := payloadContains(req.Payload, required)
		if err != nil {
			return remote.ScanResult{Target: req.Target}, err
		}
		if !found {
			return remote.ScanResult{Target: req.Target}, fmt.Errorf("payload does not contain %s", required)
		}
	}
	s.payloadPath = req.Payload

	base := req.Target.Name + "-rhel9-v2r9"
	outputPath := filepath.Join(req.OutputDir, base+".cklb")
	junitPath := filepath.Join(req.JUnitOutputDir, base+".xml")
	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		return remote.ScanResult{Target: req.Target}, err
	}
	if err := os.MkdirAll(req.JUnitOutputDir, 0o755); err != nil {
		return remote.ScanResult{Target: req.Target}, err
	}
	if err := os.WriteFile(outputPath, []byte(`{"checklist":"complete"}`), 0o600); err != nil {
		return remote.ScanResult{Target: req.Target}, err
	}
	if err := os.WriteFile(junitPath, []byte(`<testsuite name="rhel9:v2r9" tests="1"></testsuite>`), 0o600); err != nil {
		return remote.ScanResult{Target: req.Target}, err
	}
	return remote.ScanResult{
		Target: req.Target, OutputPath: outputPath, Published: true,
		JUnitOutputPath: junitPath, JUnitPublished: true,
	}, nil
}

func TestWindowsScanCommandBuildsPayloadAndPublishesReports(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	previousContentRoot := contentRoot
	contentRoot = repoRoot
	defer func() { contentRoot = previousContentRoot }()

	tempDir := t.TempDir()
	inventoryPath := filepath.Join(tempDir, "inventory.yaml")
	inventoryData := `version: 1
defaults:
  user: scanner
  profile: server
hosts:
  - name: node01
    address: node01.example.test
`
	if err := os.WriteFile(inventoryPath, []byte(inventoryData), 0o600); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(tempDir, "stigctl-linux-amd64")
	if err := os.WriteFile(binaryPath, []byte("linux-stigctl"), 0o600); err != nil {
		t.Fatal(err)
	}

	fake := &windowsControllerScanner{}
	previousFactory := newRemoteScanner
	newRemoteScanner = func() remoteScanner { return fake }
	defer func() { newRemoteScanner = previousFactory }()

	outputDir := filepath.Join(tempDir, "cklb")
	junitDir := filepath.Join(tempDir, "junit")
	cmd := newScanCommand()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"rhel9:v2r9",
		"--inventory", inventoryPath,
		"--remote-binary", binaryPath,
		"--format", "cklb",
		"--output", outputDir,
		"--junit-output", junitDir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Windows controller scan failed: %v\nstderr: %s", err, stderr.String())
	}

	for _, path := range []string{
		filepath.Join(outputDir, "node01-rhel9-v2r9.cklb"),
		filepath.Join(junitDir, "node01-rhel9-v2r9.xml"),
	} {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("report %s was not published: info=%v err=%v", path, info, err)
		}
	}
	if !strings.Contains(stdout.String(), "completed 1 remote scans") {
		t.Fatalf("unexpected controller output: %s", stdout.String())
	}
	if fake.payloadPath == "" {
		t.Fatal("scanner did not receive a payload")
	}
	if _, err := os.Stat(fake.payloadPath); !os.IsNotExist(err) {
		t.Fatalf("temporary payload was not removed: %v", err)
	}
}

func TestWindowsScanCommandRejectsCaseCollidingInventoryNames(t *testing.T) {
	tempDir := t.TempDir()
	inventoryPath := filepath.Join(tempDir, "inventory.yaml")
	inventoryData := `version: 1
defaults:
  user: scanner
hosts:
  - name: node01
    address: node01.example.test
  - name: NODE01
    address: node02.example.test
`
	if err := os.WriteFile(inventoryPath, []byte(inventoryData), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newScanCommand()
	cmd.SetArgs([]string{
		"rhel9:v2r9",
		"--inventory", inventoryPath,
		"--remote-binary", filepath.Join(tempDir, "stigctl-linux-amd64"),
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), `duplicate name "NODE01"`) {
		t.Fatalf("error = %v, want case-colliding inventory error", err)
	}
}

func payloadContains(path, required string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return false, err
	}
	defer func() { _ = gz.Close() }()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if header.Name == required {
			return true, nil
		}
	}
}
