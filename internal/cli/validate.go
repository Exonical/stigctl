package cli

import "github.com/spf13/cobra"

func newValidateCommand() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "validate <baseline>",
		Short: "Validate a STIG baseline with Goss",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "default", "system profile")
	return cmd
}
