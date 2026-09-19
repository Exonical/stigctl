package yip

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/Exonical/stigctl/internal/remediation"
)

type Runner struct {
	Binary string
}

func New(binary string) Runner {
	if binary == "" {
		binary = "yip"
	}
	return Runner{Binary: binary}
}

func (r Runner) Apply(ctx context.Context, req remediation.Request) (remediation.Result, error) {
	stage := req.Stage
	if stage == "" {
		stage = "stig"
	}
	if len(req.Files) == 0 {
		return remediation.Result{}, fmt.Errorf("no Yip remediation files supplied")
	}

	args := []string{"-s", stage}
	args = append(args, req.Files...)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.Binary, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := remediation.Result{
		Files:  append([]string(nil), req.Files...),
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if err != nil {
		return result, fmt.Errorf("yip failed: %w", err)
	}
	return result, nil
}
