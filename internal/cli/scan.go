package cli

import "github.com/spf13/cobra"

func newScanCommand() *cobra.Command {
	var (
		profile string
		format  string
		output  string
	)

	cmd := &cobra.Command{
		Use:   "scan <baseline>",
		Short: "Validate and export STIG results",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "default", "system profile")
	cmd.Flags().StringVar(&format, "format", "cklb", "output format")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file")
	return cmd
}
