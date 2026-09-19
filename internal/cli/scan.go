package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Exonical/stigctl/internal/baseline"
	stigexport "github.com/Exonical/stigctl/internal/export"
	"github.com/Exonical/stigctl/internal/export/cklb"
	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/host"
	"github.com/Exonical/stigctl/internal/policy"
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
		gossBinary     string
		failOnFindings bool
	)

	cmd := &cobra.Command{
		Use:   "scan <baseline>",
		Short: "Validate and export STIG results",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}

			gossFile, err := resolved.GossFile()
			if err != nil {
				return err
			}
			scanned, err := goss.New(gossBinary).Validate(cmd.Context(), validation.Request{
				Baseline: args[0],
				Profile:  profile,
				GossFile: gossFile,
				Package:  "rpm",
			})
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
			merged := policy.Merge(ruleDoc, exceptionDoc, scanned, policy.Context{
				Profile:  profile,
				Hostname: facts.Hostname,
				Now:      time.Now(),
			})

			if output == "" {
				ext := strings.ToLower(format)
				if ext == "json" {
					ext = "json"
				}
				name := strings.ReplaceAll(args[0], ":", "-")
				if facts.Hostname != "" {
					name = facts.Hostname + "-" + name
				}
				output = name + "." + ext
			}

			if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil && filepath.Dir(output) != "." {
				return fmt.Errorf("create output directory: %w", err)
			}
			file, err := os.Create(output)
			if err != nil {
				return fmt.Errorf("create output: %w", err)
			}
			defer file.Close()

			switch strings.ToLower(format) {
			case "json":
				enc := json.NewEncoder(file)
				enc.SetIndent("", "  ")
				if err := enc.Encode(merged); err != nil {
					return fmt.Errorf("encode JSON results: %w", err)
				}
			case "cklb":
				xccdfPath, err := resolved.XCCDFFile()
				if err != nil {
					return err
				}
				source, err := os.Open(xccdfPath)
				if err != nil {
					return fmt.Errorf("open XCCDF source: %w", err)
				}
				benchmark, parseErr := xccdf.Parse(source)
				source.Close()
				if parseErr != nil {
					return parseErr
				}

				if err := (cklb.Exporter{}).Export(cmd.Context(), file, stigexport.Request{
					Baseline:  args[0],
					Benchmark: benchmark,
					Target: stigexport.Target{
						Hostname: facts.Hostname,
					},
					Results: merged,
				}); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported format %q: use cklb or json", format)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%s)\n", output, policy.Summary(merged))
			if failOnFindings && policy.HasFailures(merged) {
				return fmt.Errorf("STIG scan contains open findings or validation errors")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "default", "system profile")
	cmd.Flags().StringVar(&format, "format", "cklb", "output format: cklb or json")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")
	cmd.Flags().StringVar(&gossBinary, "goss-binary", "goss", "path to the Goss executable")
	cmd.Flags().BoolVar(&failOnFindings, "fail-on-findings", false, "exit non-zero after writing results when findings exist")
	return cmd
}
