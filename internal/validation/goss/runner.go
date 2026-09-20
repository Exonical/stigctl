//go:build linux

package goss

import (
	"context"
	"fmt"

	"github.com/Exonical/stigctl/internal/results"
	"github.com/Exonical/stigctl/internal/validation"
	gosslib "github.com/goss-org/goss"
	"github.com/goss-org/goss/resource"
	gossutil "github.com/goss-org/goss/util"
)

type Runner struct{}

func New() Runner {
	return Runner{}
}

func (Runner) Validate(ctx context.Context, req validation.Request) ([]results.Result, error) {
	if req.GossFile == "" {
		return nil, fmt.Errorf("goss file is required")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(req.Vars) > 1 {
		return nil, fmt.Errorf("embedded Goss v0.4.10 supports one vars file, got %d", len(req.Vars))
	}

	options := []gossutil.ConfigOption{
		gossutil.WithSpecFile(req.GossFile),
		gossutil.WithPackageManager(req.Package),
		gossutil.WithMaxConcurrency(50),
	}
	if len(req.Vars) == 1 {
		options = append(options, gossutil.WithVarsFile(req.Vars[0]))
	}
	config, err := gossutil.NewConfig(options...)
	if err != nil {
		return nil, fmt.Errorf("configure embedded Goss: %w", err)
	}

	ch, err := gosslib.ValidateResults(config)
	if err != nil {
		return nil, fmt.Errorf("embedded Goss validation setup failed: %w", err)
	}

	var tests []resource.TestResult
	for batch := range ch {
		tests = append(tests, batch...)
	}
	return normalizeResults(tests), nil
}
