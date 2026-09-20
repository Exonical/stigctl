//go:build linux

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/exceptions"
	stigexport "github.com/Exonical/stigctl/internal/export"
	"github.com/Exonical/stigctl/internal/export/cklb"
	"github.com/Exonical/stigctl/internal/export/junit"
	"github.com/Exonical/stigctl/internal/host"
	"github.com/Exonical/stigctl/internal/policy"
	"github.com/Exonical/stigctl/internal/results"
	"github.com/Exonical/stigctl/internal/rules"
	"github.com/Exonical/stigctl/internal/validation"
	"github.com/Exonical/stigctl/internal/validation/goss"
	"github.com/Exonical/stigctl/internal/xccdf"
	"github.com/spf13/cobra"
)

func newScanCommand() *cobra.Command {
	var (
		profile        string
		format         string
		output         string
		failOnFindings bool
		hostname       string
		ipAddress      string
		macAddress     string
		fqdn           string
		role           string
		targetComments string
		cklbTemplate   string
		inventoryFile  string
		concurrency    int
		junitOutput    string
		remoteBinary   string
	)

	cmd := &cobra.Command{
		Use:   "scan <baseline>",
		Short: "Validate and export STIG results",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if junitOutput != "" && strings.EqualFold(format, "junit") {
				return fmt.Errorf("--junit-output cannot be combined with --format junit")
			}
			if inventoryFile != "" {
				for _, flag := range []string{"hostname", "ip-address", "mac-address", "fqdn", "role", "target-comments", "cklb-template"} {
					if cmd.Flags().Changed(flag) {
						return fmt.Errorf("--%s cannot be used with --inventory; set per-host metadata in the inventory", flag)
					}
				}
				return runRemoteScans(cmd, remoteScanOptions{
					Baseline: args[0], InventoryFile: inventoryFile, Format: format,
					OutputDir: output, JUnitOutputDir: junitOutput, Profile: profile,
					RemoteBinary: remoteBinary, FailOnFindings: failOnFindings, Concurrency: concurrency,
				})
			}
			if junitOutput != "" && output != "" && filepath.Clean(junitOutput) == filepath.Clean(output) {
				return fmt.Errorf("--junit-output and --output must use different files")
			}
			if err := validateProfile(profile); err != nil {
				return err
			}
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}

			gossFile, err := resolved.GossFile()
			if err != nil {
				return err
			}

			ruleDoc, err := rules.Load(resolved.RulesFile())
			if err != nil {
				return err
			}
			exceptionDoc, err := exceptions.Load(resolved.ExceptionsFile())
			if err != nil {
				return err
			}

			facts := host.Detect()
			if hostname == "" {
				hostname = facts.Hostname
			}

			varsFile, cleanup, err := writeEffectiveGossVars(ruleDoc, exceptionDoc, profile, hostname)
			if err != nil {
				return err
			}
			defer cleanup()

			scanned, err := goss.New().Validate(cmd.Context(), validation.Request{
				Baseline: args[0],
				Profile:  profile,
				GossFile: gossFile,
				Vars:     []string{varsFile},
				Package:  "rpm",
			})
			if err != nil {
				return err
			}

			merged := policy.Merge(ruleDoc, exceptionDoc, scanned, policy.Context{
				Profile:  profile,
				Hostname: hostname,
				Now:      time.Now(),
			})

			if output == "" {
				ext := outputExtension(format)
				name := strings.ReplaceAll(args[0], ":", "-")
				if hostname != "" {
					name = hostname + "-" + name
				}
				output = name + "." + ext
			}

			dir := filepath.Dir(output)
			if dir != "." {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return fmt.Errorf("create output directory: %w", err)
				}
			}

			file, err := os.Create(output)
			if err != nil {
				return fmt.Errorf("create output: %w", err)
			}
			defer func() { _ = file.Close() }()

			switch strings.ToLower(format) {
			case "json":
				enc := json.NewEncoder(file)
				enc.SetIndent("", "  ")
				if err := enc.Encode(merged); err != nil {
					return fmt.Errorf("encode JSON results: %w", err)
				}
			case "junit":
				req := stigexport.Request{
					Baseline: args[0],
					Target: stigexport.Target{
						Hostname:  hostname,
						IPAddress: ipAddress,
						FQDN:      fqdn,
					},
					Results: merged,
				}
				if err := (junit.Exporter{}).Export(cmd.Context(), file, req); err != nil {
					return err
				}
			case "cklb":
				req := stigexport.Request{
					Baseline: args[0],
					Target: stigexport.Target{
						Hostname:   hostname,
						IPAddress:  ipAddress,
						MACAddress: macAddress,
						FQDN:       fqdn,
						Comments:   targetComments,
						Role:       role,
					},
					Results: merged,
				}

				templatePath := cklbTemplate
				if templatePath == "" {
					templatePath, err = resolved.CKLBTemplateFile()
					if err != nil {
						return err
					}
				}

				if templatePath != "" {
					template, err := cklb.LoadFile(templatePath)
					if err != nil {
						return err
					}
					doc, err := cklb.Overlay(template, req)
					if err != nil {
						return err
					}
					if err := cklb.Write(file, doc); err != nil {
						return err
					}
				} else {
					xccdfPath, err := resolved.XCCDFFile()
					if err != nil {
						return err
					}
					source, err := os.Open(xccdfPath)
					if err != nil {
						return fmt.Errorf("open XCCDF source: %w", err)
					}
					benchmark, parseErr := xccdf.Parse(source)
					_ = source.Close()
					if parseErr != nil {
						return parseErr
					}
					req.Benchmark = benchmark
					if err := (cklb.Exporter{}).Export(cmd.Context(), file, req); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("unsupported format %q: use cklb, json, or junit", format)
			}
			if err := file.Close(); err != nil {
				return fmt.Errorf("close output: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%s)\n", output, policy.Summary(merged))
			if junitOutput != "" {
				if err := writeJUnitReport(cmd, args[0], junitOutput, hostname, ipAddress, fqdn, merged); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%s)\n", junitOutput, policy.Summary(merged))
			}
			if failOnFindings && policy.HasFailures(merged) {
				return fmt.Errorf("STIG scan contains open findings or validation errors")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "default", "system profile")
	cmd.Flags().StringVar(&format, "format", "cklb", "output format: cklb, json, or junit")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file, or directory with --inventory")
	cmd.Flags().BoolVar(&failOnFindings, "fail-on-findings", false, "exit non-zero after writing results when findings exist")
	cmd.Flags().StringVar(&hostname, "hostname", "", "target hostname; defaults to the local hostname")
	cmd.Flags().StringVar(&ipAddress, "ip-address", "", "target IP address for CKLB metadata")
	cmd.Flags().StringVar(&macAddress, "mac-address", "", "target MAC address for CKLB metadata")
	cmd.Flags().StringVar(&fqdn, "fqdn", "", "target FQDN for CKLB metadata")
	cmd.Flags().StringVar(&role, "role", "None", "STIG Viewer target role")
	cmd.Flags().StringVar(&targetComments, "target-comments", "", "comments stored in CKLB target metadata")
	cmd.Flags().StringVar(&cklbTemplate, "cklb-template", "", "STIG Viewer 3 CKLB template; preserves official checklist metadata and UUIDs")
	cmd.Flags().StringVar(&inventoryFile, "inventory", "", "scan hosts from a YAML SSH inventory; output is treated as a directory")
	cmd.Flags().IntVar(&concurrency, "concurrency", 4, "maximum concurrent inventory scans")
	cmd.Flags().StringVar(&junitOutput, "junit-output", "", "also write JUnit XML; with --inventory, this is an output directory")
	cmd.Flags().StringVar(&remoteBinary, "remote-binary", "", "stigctl executable to stage on inventory targets; defaults to the current binary")
	return cmd
}

func writeJUnitReport(
	cmd *cobra.Command,
	baselineRef string,
	path string,
	hostname string,
	ipAddress string,
	fqdn string,
	merged []results.Result,
) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create JUnit output directory: %w", err)
		}
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create JUnit output: %w", err)
	}
	exportErr := (junit.Exporter{}).Export(cmd.Context(), file, stigexport.Request{
		Baseline: baselineRef,
		Target: stigexport.Target{
			Hostname:  hostname,
			IPAddress: ipAddress,
			FQDN:      fqdn,
		},
		Results: merged,
	})
	closeErr := file.Close()
	if exportErr != nil && closeErr != nil {
		return errors.Join(exportErr, fmt.Errorf("close JUnit output: %w", closeErr))
	}
	if exportErr != nil {
		return exportErr
	}
	if closeErr != nil {
		return fmt.Errorf("close JUnit output: %w", closeErr)
	}
	return nil
}
