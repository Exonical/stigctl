package cli

import "github.com/spf13/cobra"

func newApplyCommand() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "apply <baseline>",
		Short: "Apply STIG remediation with Yip",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "default", "system profile")
	return cmd
}
