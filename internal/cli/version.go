package cli

import (
	"fmt"

	"github.com/Exonical/stigctl/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print stigctl version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "stigctl "+version.String())
		},
	}
}
