package cli

import "github.com/spf13/cobra"

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stigctl",
		Short: "Enterprise Linux STIG lifecycle CLI",
		Long:  "Apply STIG remediation with Yip, validate with Goss, manage exceptions, and export CKLB checklists.",
	}

	cmd.AddCommand(
		newApplyCommand(),
		newValidateCommand(),
		newScanCommand(),
		newBaselineCommand(),
		newExceptionsCommand(),
	)

	return cmd
}
