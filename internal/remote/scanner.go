package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/stigctl/internal/inventory"
)

type ScanRequest struct {
	Baseline       string
	Format         string
	OutputDir      string
	JUnitOutputDir string
	Payload        string
	Binary         string
	FailOnFindings bool
	Target         inventory.Target
}

type ScanResult struct {
	Target          inventory.Target
	OutputPath      string
	Published       bool
	JUnitOutputPath string
	JUnitPublished  bool
	Stdout          string
	Stderr          string
	ExitCode        int
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

type Options struct {
	SSH string
	SCP string
}

type Scanner struct {
	runner commandRunner
	ssh    string
	scp    string
}

const cleanupTimeout = 30 * time.Second

func NewScanner(options Options) Scanner {
	return Scanner{runner: execRunner{}, ssh: options.SSH, scp: options.SCP}
}

func (s Scanner) Scan(ctx context.Context, req ScanRequest) (result ScanResult, retErr error) {
	if req.Target.ScanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Target.ScanTimeout)
		defer cancel()
	}

	result.Target = req.Target
	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		return result, fmt.Errorf("create remote scan output directory: %w", err)
	}
	extension := artifactExtension(req.Format)
	result.OutputPath = filepath.Join(req.OutputDir, req.Target.Name+"-"+strings.ReplaceAll(req.Baseline, ":", "-")+"."+extension)
	if req.JUnitOutputDir != "" {
		if err := os.MkdirAll(req.JUnitOutputDir, 0o755); err != nil {
			return result, fmt.Errorf("create remote JUnit output directory: %w", err)
		}
		result.JUnitOutputPath = filepath.Join(req.JUnitOutputDir, req.Target.Name+"-"+strings.ReplaceAll(req.Baseline, ":", "-")+".xml")
	}

	remoteDir, err := s.makeRemoteDir(ctx, req.Target)
	if err != nil {
		return result, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		cleanupErr := s.cleanup(cleanupCtx, req.Target, remoteDir)
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

	remoteOutput := remoteDir + "/result." + extension
	remoteJUnitOutput := ""
	if req.JUnitOutputDir != "" {
		remoteJUnitOutput = remoteDir + "/result.xml"
	}
	command := buildScanCommand(req, remoteDir, remoteOutput, remoteJUnitOutput)
	var stdout, stderr bytes.Buffer
	runErr := s.runner.Run(ctx, s.sshBinary(), append(sshArgs(req.Target), destination(req.Target), command), &stdout, &stderr)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.ExitCode = exitCode(runErr)

	var artifactErrs []error
	result.Published, err = s.collectArtifact(ctx, req.Target, remoteOutput, result.OutputPath, req.Format)
	if err != nil {
		artifactErrs = append(artifactErrs, fmt.Errorf("primary report: %w", err))
	}
	if remoteJUnitOutput != "" {
		result.JUnitPublished, err = s.collectArtifact(ctx, req.Target, remoteJUnitOutput, result.JUnitOutputPath, "junit")
		if err != nil {
			artifactErrs = append(artifactErrs, fmt.Errorf("JUnit report: %w", err))
		}
	}
	if runErr != nil {
		runError := fmt.Errorf("scan %s exited with status %d: %s", req.Target.Name, result.ExitCode, strings.TrimSpace(result.Stderr))
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			runError = fmt.Errorf("scan %s timed out after %s", req.Target.Name, req.Target.ScanTimeout)
		}
		artifactErrs = append([]error{runError}, artifactErrs...)
	}
	if len(artifactErrs) > 0 {
		return result, errors.Join(artifactErrs...)
	}
	return result, nil
}

func (s Scanner) collectArtifact(
	ctx context.Context,
	target inventory.Target,
	remotePath string,
	outputPath string,
	format string,
) (bool, error) {
	tempFile, err := os.CreateTemp(filepath.Dir(outputPath), "."+filepath.Base(outputPath)+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("create temporary artifact: %w", err)
	}
	tempPath := tempFile.Name()
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return false, fmt.Errorf("close temporary artifact: %w", err)
	}
	defer func() { _ = os.Remove(tempPath) }()

	if err := s.copyFrom(ctx, target, remotePath, tempPath); err != nil {
		return false, fmt.Errorf("collect artifact: %w", err)
	}
	if err := validateArtifact(tempPath, format); err != nil {
		return false, fmt.Errorf("validate artifact: %w", err)
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		return false, fmt.Errorf("publish artifact: %w", err)
	}
	return true, nil
}

func validateArtifact(path, format string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("artifact is empty")
	}
	switch strings.ToLower(format) {
	case "junit":
		var document struct {
			XMLName xml.Name
		}
		if err := xml.Unmarshal(data, &document); err != nil {
			return fmt.Errorf("artifact is not valid XML: %w", err)
		}
		if document.XMLName.Local != "testsuite" && document.XMLName.Local != "testsuites" {
			return fmt.Errorf("artifact root element is %q, expected testsuite or testsuites", document.XMLName.Local)
		}
	default:
		if !json.Valid(data) {
			return fmt.Errorf("artifact is not valid JSON")
		}
	}
	return nil
}

func artifactExtension(format string) string {
	if strings.EqualFold(format, "junit") {
		return "xml"
	}
	return strings.ToLower(format)
}

func (s Scanner) makeRemoteDir(ctx context.Context, target inventory.Target) (string, error) {
	var stdout, stderr bytes.Buffer
	err := s.runner.Run(ctx, s.sshBinary(), append(sshArgs(target), destination(target), "mktemp -d /var/tmp/stigctl-remote.XXXXXX"), &stdout, &stderr)
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
	if err := s.runner.Run(ctx, s.sshBinary(), append(sshArgs(target), destination(target), command), &stdout, &stderr); err != nil {
		return fmt.Errorf("clean remote workspace on %s: %w: %s", target.Name, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (s Scanner) copyTo(ctx context.Context, target inventory.Target, source, remotePath string) error {
	var stdout, stderr bytes.Buffer
	args := append(scpArgs(target), source, scpDestination(target, remotePath))
	if err := s.runner.Run(ctx, s.scpBinary(), args, &stdout, &stderr); err != nil {
		return fmt.Errorf("scp: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (s Scanner) copyFrom(ctx context.Context, target inventory.Target, remotePath, destinationPath string) error {
	var stdout, stderr bytes.Buffer
	args := append(scpArgs(target), scpDestination(target, remotePath), destinationPath)
	if err := s.runner.Run(ctx, s.scpBinary(), args, &stdout, &stderr); err != nil {
		return fmt.Errorf("scp: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func buildScanCommand(req ScanRequest, remoteDir, output, junitOutput string) string {
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
	appendValue("--junit-output", junitOutput)

	outputs := []string{output}
	if junitOutput != "" {
		outputs = append(outputs, junitOutput)
	}
	quotedOutputs := make([]string, 0, len(outputs))
	for _, path := range outputs {
		quotedOutputs = append(quotedOutputs, shellQuote(path))
	}
	command := "set -eu; touch " + strings.Join(quotedOutputs, " ") + "; chmod 600 " + strings.Join(quotedOutputs, " ") +
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
	if target.ConnectTimeout > 0 {
		seconds := max(int64(math.Ceil(target.ConnectTimeout.Seconds())), 1)
		args = append(args, "-o", "ConnectTimeout="+strconv.FormatInt(seconds, 10))
	}
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
	if target.ConnectTimeout > 0 {
		seconds := max(int64(math.Ceil(target.ConnectTimeout.Seconds())), 1)
		args = append(args, "-o", "ConnectTimeout="+strconv.FormatInt(seconds, 10))
	}
	if target.IdentityFile != "" {
		args = append(args, "-i", target.IdentityFile, "-o", "IdentitiesOnly=yes")
	}
	if target.KnownHostsFile != "" {
		args = append(args, "-o", "UserKnownHostsFile="+target.KnownHostsFile)
	}
	return args
}

func (s Scanner) sshBinary() string {
	if s.ssh == "" {
		return "ssh"
	}
	return s.ssh
}

func (s Scanner) scpBinary() string {
	if s.scp == "" {
		return "scp"
	}
	return s.scp
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
