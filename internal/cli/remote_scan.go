package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
	JUnitOutputDir string
	Profile        string
	RemoteBinary   string
	FailOnFindings bool
	Concurrency    int
	ConnectTimeout time.Duration
	HostTimeout    time.Duration
	SSHBinary      string
	SCPBinary      string
}

type remoteScanner interface {
	Scan(context.Context, remote.ScanRequest) (remote.ScanResult, error)
}

var newRemoteScanner = func(options remote.Options) remoteScanner {
	return remote.NewScanner(options)
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
		if targets[i].ConnectTimeout == 0 {
			targets[i].ConnectTimeout = options.ConnectTimeout
		}
		if targets[i].ScanTimeout == 0 {
			targets[i].ScanTimeout = options.HostTimeout
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
	binary := options.RemoteBinary
	if binary == "" {
		binary, err = os.Executable()
		if err != nil {
			return fmt.Errorf("locate stigctl executable: %w", err)
		}
	} else {
		binary, err = filepath.Abs(binary)
		if err != nil {
			return fmt.Errorf("resolve remote binary: %w", err)
		}
		info, statErr := os.Stat(binary)
		if statErr != nil {
			return fmt.Errorf("remote binary %q: %w", binary, statErr)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("remote binary %q is not a regular file", binary)
		}
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
			scanner := newRemoteScanner(remote.Options{SSH: options.SSHBinary, SCP: options.SCPBinary})
			result, scanErr := scanner.Scan(cmd.Context(), remote.ScanRequest{
				Baseline: options.Baseline, Format: format, OutputDir: outputDir,
				JUnitOutputDir: options.JUnitOutputDir,
				Payload:        payload, Binary: binary, FailOnFindings: options.FailOnFindings,
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
		if item.result.JUnitPublished && item.result.JUnitOutputPath != "" {
			if info, statErr := os.Stat(item.result.JUnitOutputPath); statErr == nil && info.Size() > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "[%s] wrote %s\n", item.result.Target.Name, item.result.JUnitOutputPath)
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
