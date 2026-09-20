package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Exonical/stigctl/internal/inventory"
)

type ScanRequest struct {
	Baseline       string
	Format         string
	OutputDir      string
	Payload        string
	Binary         string
	FailOnFindings bool
	Target         inventory.Target
}

type ScanResult struct {
	Target     inventory.Target
	OutputPath string
	Stdout     string
	Stderr     string
	ExitCode   int
}

type commandRunner interface {
	Run(context.Context, string, []string, *bytes.Buffer, *bytes.Buffer) error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args []string, stdout, stderr *bytes.Buffer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

type Scanner struct {
	runner commandRunner
}

func NewScanner() Scanner {
	return Scanner{runner: execRunner{}}
}

func (s Scanner) Scan(ctx context.Context, req ScanRequest) (result ScanResult, retErr error) {
	result.Target = req.Target
	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		return result, fmt.Errorf("create remote scan output directory: %w", err)
	}
	result.OutputPath = filepath.Join(req.OutputDir, req.Target.Name+"-"+strings.ReplaceAll(req.Baseline, ":", "-")+"."+req.Format)

	remoteDir, err := s.makeRemoteDir(ctx, req.Target)
	if err != nil {
		return result, err
	}
	defer func() {
		cleanupErr := s.cleanup(ctx, req.Target, remoteDir)
		if cleanupErr != nil {
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()

	if err := s.copyTo(ctx, req.Target, req.Binary, remoteDir+"/stigctl"); err != nil {
		return result, fmt.Errorf("stage stigctl on %s: %w", req.Target.Name, err)
	}
	if err := s.copyTo(ctx, req.Target, req.Payload, remoteDir+"/payload.tar.gz"); err != nil {
		return result, fmt.Errorf("stage baseline on %s: %w", req.Target.Name, err)
	}

	remoteOutput := remoteDir + "/result." + req.Format
	command := buildScanCommand(req, remoteDir, remoteOutput)
	var stdout, stderr bytes.Buffer
	runErr := s.runner.Run(ctx, "ssh", append(sshArgs(req.Target), destination(req.Target), command), &stdout, &stderr)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.ExitCode = exitCode(runErr)

	copyErr := s.copyFrom(ctx, req.Target, remoteOutput, result.OutputPath)
	if copyErr != nil {
		_ = os.Remove(result.OutputPath)
		if runErr != nil {
			return result, fmt.Errorf("scan %s: %w: %s", req.Target.Name, runErr, strings.TrimSpace(result.Stderr))
		}
		return result, fmt.Errorf("collect scan from %s: %w", req.Target.Name, copyErr)
	}
	if runErr != nil {
		return result, fmt.Errorf("scan %s exited with status %d: %s", req.Target.Name, result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	return result, nil
}

func (s Scanner) makeRemoteDir(ctx context.Context, target inventory.Target) (string, error) {
	var stdout, stderr bytes.Buffer
	err := s.runner.Run(ctx, "ssh", append(sshArgs(target), destination(target), "mktemp -d /var/tmp/stigctl-remote.XXXXXX"), &stdout, &stderr)
	if err != nil {
		return "", fmt.Errorf("create remote workspace on %s: %w: %s", target.Name, err, strings.TrimSpace(stderr.String()))
	}
	path := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(path, "/var/tmp/stigctl-remote.") || strings.ContainsAny(path, " \t\r\n'") {
		return "", fmt.Errorf("host %s returned unsafe temporary path %q", target.Name, path)
	}
	return path, nil
}

func (s Scanner) cleanup(ctx context.Context, target inventory.Target, remoteDir string) error {
	var stdout, stderr bytes.Buffer
	command := "rm -rf -- " + shellQuote(remoteDir)
	if err := s.runner.Run(ctx, "ssh", append(sshArgs(target), destination(target), command), &stdout, &stderr); err != nil {
		return fmt.Errorf("clean remote workspace on %s: %w: %s", target.Name, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (s Scanner) copyTo(ctx context.Context, target inventory.Target, source, remotePath string) error {
	var stdout, stderr bytes.Buffer
	args := append(scpArgs(target), source, scpDestination(target, remotePath))
	if err := s.runner.Run(ctx, "scp", args, &stdout, &stderr); err != nil {
		return fmt.Errorf("scp: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (s Scanner) copyFrom(ctx context.Context, target inventory.Target, remotePath, destinationPath string) error {
	var stdout, stderr bytes.Buffer
	args := append(scpArgs(target), scpDestination(target, remotePath), destinationPath)
	if err := s.runner.Run(ctx, "scp", args, &stdout, &stderr); err != nil {
		return fmt.Errorf("scp: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func buildScanCommand(req ScanRequest, remoteDir, output string) string {
	args := []string{remoteDir + "/stigctl", "--content-root", remoteDir + "/content", "scan", req.Baseline,
		"--profile", req.Target.Profile, "--format", req.Format, "--output", output,
	}
	if req.FailOnFindings {
		args = append(args, "--fail-on-findings")
	}
	appendValue := func(flag, value string) {
		if value != "" {
			args = append(args, flag, value)
		}
	}
	appendValue("--hostname", req.Target.Hostname)
	appendValue("--ip-address", req.Target.IPAddress)
	appendValue("--mac-address", req.Target.MACAddress)
	appendValue("--fqdn", req.Target.FQDN)
	appendValue("--role", req.Target.Role)
	appendValue("--target-comments", req.Target.Comments)

	command := "set -eu; touch " + shellQuote(output) + "; chmod 600 " + shellQuote(output) +
		"; tar -xzf " + shellQuote(remoteDir+"/payload.tar.gz") + " -C " + shellQuote(remoteDir) +
		"; chmod 700 " + shellQuote(remoteDir+"/stigctl") + "; "
	if req.Target.Sudo {
		command += "sudo -n -- "
	}
	for i, arg := range args {
		if i > 0 {
			command += " "
		}
		command += shellQuote(arg)
	}
	return command
}

func sshArgs(target inventory.Target) []string {
	args := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-p", strconv.Itoa(target.Port)}
	if target.IdentityFile != "" {
		args = append(args, "-i", target.IdentityFile, "-o", "IdentitiesOnly=yes")
	}
	if target.KnownHostsFile != "" {
		args = append(args, "-o", "UserKnownHostsFile="+target.KnownHostsFile)
	}
	return args
}

func scpArgs(target inventory.Target) []string {
	args := []string{"-q", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-P", strconv.Itoa(target.Port)}
	if target.IdentityFile != "" {
		args = append(args, "-i", target.IdentityFile, "-o", "IdentitiesOnly=yes")
	}
	if target.KnownHostsFile != "" {
		args = append(args, "-o", "UserKnownHostsFile="+target.KnownHostsFile)
	}
	return args
}

func destination(target inventory.Target) string {
	return target.User + "@" + target.Address
}

func scpDestination(target inventory.Target, path string) string {
	address := target.Address
	if strings.Contains(address, ":") {
		address = "[" + address + "]"
	}
	return target.User + "@" + address + ":" + path
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
