package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/rules"
	"github.com/Exonical/stigctl/internal/xccdf"
	"github.com/spf13/cobra"
)

func newBaselineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Inspect and maintain STIG baselines",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List available baselines",
			RunE: func(cmd *cobra.Command, args []string) error {
				items, err := baseline.NewStore(contentRoot).List()
				if err != nil {
					return err
				}
				for _, item := range items {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"%-16s %s (implementation %d) [%s]\n",
						item.Ref,
						item.Manifest.Baseline.DisplayName,
						item.Manifest.Implementation.Revision,
						item.Manifest.Status,
					)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "show <baseline>",
			Short: "Show baseline metadata",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				item, err := baseline.NewStore(contentRoot).Resolve(args[0])
				if err != nil {
					return err
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(item.Manifest)
			},
		},
		newBaselineSyncCommand(),
	)

	return cmd
}

func newBaselineSyncCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "sync <baseline>",
		Short: "Refresh rules.yaml metadata from the authoritative XCCDF",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}
			xccdfPath, err := resolved.XCCDFFile()
			if err != nil {
				return err
			}
			file, err := os.Open(xccdfPath)
			if err != nil {
				return fmt.Errorf("open XCCDF source: %w", err)
			}
			defer file.Close()

			benchmark, err := xccdf.Parse(file)
			if err != nil {
				return err
			}
			existing, err := rules.Load(resolved.RulesFile())
			if err != nil {
				return err
			}
			synced := rules.Sync(existing, benchmark)
			if err := rules.Save(resolved.RulesFile(), synced); err != nil {
				return err
			}

			fmt.Fprintf(
				cmd.OutOrStdout(),
				"synced %d rules from %s into %s\n",
				len(benchmark.Rules),
				xccdfPath,
				resolved.RulesFile(),
			)
			return nil
		},
	}
}
