package goss

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/Exonical/stigctl/internal/results"
	"github.com/Exonical/stigctl/internal/validation"
)

type Runner struct {
	Binary string
}

func New(binary string) Runner {
	if binary == "" {
		binary = "goss"
	}
	return Runner{Binary: binary}
}

func (r Runner) Validate(ctx context.Context, req validation.Request) ([]results.Result, error) {
	if req.GossFile == "" {
		return nil, fmt.Errorf("goss file is required")
	}

	args := []string{"-g", req.GossFile}
	for _, vars := range req.Vars {
		args = append(args, "--vars", vars)
	}
	if req.Package != "" {
		args = append(args, "--package", req.Package)
	}
	args = append(args, "validate", "--format", "json", "--format-options", "sort")

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.Binary, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	parsed, parseErr := Parse(bytes.NewReader(stdout.Bytes()))
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("goss failed (%v), stderr: %s; parse output: %w", runErr, stderr.String(), parseErr)
		}
		return nil, parseErr
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) && exitErr.ExitCode() == 1 {
			// Goss uses exit code 1 when validation has findings. Parsed results are authoritative.
			return parsed, nil
		}
		return parsed, fmt.Errorf("goss execution failed: %w: %s", runErr, stderr.String())
	}

	return parsed, nil
}
