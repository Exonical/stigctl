package cli

import "github.com/spf13/cobra"

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
				return cmd.Help()
			},
		},
		&cobra.Command{
			Use:   "show <baseline>",
			Short: "Show baseline metadata",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return cmd.Help()
			},
		},
	)

	return cmd
}
