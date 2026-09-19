package cli

import "github.com/spf13/cobra"

func newExceptionsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exceptions",
		Short: "Inspect STIG exceptions",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list <baseline>",
			Short: "List exceptions",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return cmd.Help()
			},
		},
		&cobra.Command{
			Use:   "show <baseline> <vuln-id>",
			Short: "Show an exception",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				return cmd.Help()
			},
		},
	)

	return cmd
}
