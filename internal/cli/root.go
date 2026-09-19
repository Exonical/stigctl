package cli

import (
	"github.com/Exonical/stigctl/internal/version"
	"github.com/spf13/cobra"
)

var contentRoot string

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "stigctl",
		Short:   "Enterprise Linux STIG lifecycle CLI",
		Long:    "Apply STIG remediation with Yip, validate with Goss, manage exceptions, and export CKLB checklists.",
		Version: version.Version,
	}

	cmd.PersistentFlags().StringVar(&contentRoot, "content-root", ".", "root directory containing the stig/ baseline tree")

	cmd.AddCommand(
		newApplyCommand(),
		newValidateCommand(),
		newScanCommand(),
		newBaselineCommand(),
		newExceptionsCommand(),
		newProfileCommand(),
		newVersionCommand(),
	)

	return cmd
}
