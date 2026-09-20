//go:build !linux

package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newScanCommand() *cobra.Command {
	var (
		profile        string
		format         string
		output         string
		junitOutput    string
		failOnFindings bool
		inventoryFile  string
		remoteBinary   string
		concurrency    int
	)

	cmd := &cobra.Command{
		Use:   "scan <baseline>",
		Short: "Scan a Linux SSH inventory from this controller",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if inventoryFile == "" {
				return fmt.Errorf("local STIG scanning is supported only on Linux; provide --inventory and a Linux --remote-binary")
			}
			if remoteBinary == "" {
				return fmt.Errorf("--remote-binary is required on non-Linux controllers and must reference a Linux stigctl executable")
			}
			if junitOutput != "" && strings.EqualFold(format, "junit") {
				return fmt.Errorf("--junit-output cannot be combined with --format junit")
			}
			return runRemoteScans(cmd, remoteScanOptions{
				Baseline: args[0], InventoryFile: inventoryFile, Format: format,
				OutputDir: output, JUnitOutputDir: junitOutput, Profile: profile,
				RemoteBinary: remoteBinary, FailOnFindings: failOnFindings, Concurrency: concurrency,
			})
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "default", "system profile")
	cmd.Flags().StringVar(&format, "format", "cklb", "output format: cklb, json, or junit")
	cmd.Flags().StringVarP(&output, "output", "o", "", "inventory output directory")
	cmd.Flags().StringVar(&junitOutput, "junit-output", "", "also write JUnit XML to this output directory")
	cmd.Flags().BoolVar(&failOnFindings, "fail-on-findings", false, "exit non-zero after writing results when findings exist")
	cmd.Flags().StringVar(&inventoryFile, "inventory", "", "scan hosts from a YAML SSH inventory")
	cmd.Flags().StringVar(&remoteBinary, "remote-binary", "", "Linux stigctl executable to stage on inventory targets")
	cmd.Flags().IntVar(&concurrency, "concurrency", 4, "maximum concurrent inventory scans")
	return cmd
}
