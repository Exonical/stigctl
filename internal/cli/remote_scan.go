package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/inventory"
	"github.com/Exonical/stigctl/internal/remote"
	"github.com/spf13/cobra"
)

type remoteScanOptions struct {
	Baseline       string
	InventoryFile  string
	Format         string
	OutputDir      string
	Profile        string
	FailOnFindings bool
	Concurrency    int
}

func runRemoteScans(cmd *cobra.Command, options remoteScanOptions) error {
	format := strings.ToLower(options.Format)
	if format != "cklb" && format != "json" && format != "junit" {
		return fmt.Errorf("unsupported format %q: use cklb, json, or junit", options.Format)
	}
	if options.Concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1")
	}
	targets, err := inventory.Load(options.InventoryFile)
	if err != nil {
		return err
	}
	profiles := make([]string, 0, len(targets))
	for i := range targets {
		if targets[i].Profile == "" {
			targets[i].Profile = options.Profile
		}
		target := targets[i]
		if err := validateProfile(target.Profile); err != nil {
			return fmt.Errorf("inventory host %s: %w", target.Name, err)
		}
		profiles = append(profiles, target.Profile)
	}
	resolved, err := baseline.NewStore(contentRoot).Resolve(options.Baseline)
	if err != nil {
		return err
	}
	payload, cleanup, err := remote.CreatePayload(contentRoot, resolved, profiles)
	if err != nil {
		return err
	}
	defer cleanup()
	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate stigctl executable: %w", err)
	}
	outputDir := options.OutputDir
	if outputDir == "" {
		outputDir = "stigctl-results"
	}

	type indexedResult struct {
		index  int
		result remote.ScanResult
		err    error
	}
	results := make(chan indexedResult, len(targets))
	limit := make(chan struct{}, options.Concurrency)
	var wg sync.WaitGroup
	for i, target := range targets {
		fmt.Fprintf(cmd.OutOrStdout(), "[%s] starting transient SSH scan\n", target.Name)
		wg.Add(1)
		go func() {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			scanner := remote.NewScanner()
			result, scanErr := scanner.Scan(cmd.Context(), remote.ScanRequest{
				Baseline: options.Baseline, Format: format, OutputDir: outputDir,
				Payload: payload, Binary: binary, FailOnFindings: options.FailOnFindings,
				Target: target,
			})
			results <- indexedResult{index: i, result: result, err: scanErr}
		}()
	}
	wg.Wait()
	close(results)

	ordered := make([]indexedResult, len(targets))
	for result := range results {
		ordered[result.index] = result
	}
	var scanErrors []error
	for _, item := range ordered {
		if item.result.Published && item.result.OutputPath != "" {
			if info, statErr := os.Stat(item.result.OutputPath); statErr == nil && info.Size() > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "[%s] wrote %s\n", item.result.Target.Name, item.result.OutputPath)
			}
		}
		if item.err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "[%s] %v\n", item.result.Target.Name, item.err)
			scanErrors = append(scanErrors, item.err)
		}
	}
	if len(scanErrors) > 0 {
		return fmt.Errorf("%d of %d remote scans failed: %w", len(scanErrors), len(targets), errors.Join(scanErrors...))
	}
	fmt.Fprintf(cmd.OutOrStdout(), "completed %d remote scans\n", len(targets))
	return nil
}
