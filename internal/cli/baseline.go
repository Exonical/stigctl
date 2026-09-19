package cli

import (
	"encoding/json"
	"fmt"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/spf13/cobra"
)

func newBaselineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Inspect STIG baselines",
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
	)

	return cmd
}
