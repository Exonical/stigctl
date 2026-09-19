package cli

import (
	"fmt"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/remediation"
	"github.com/Exonical/stigctl/internal/remediation/yip"
	"github.com/spf13/cobra"
)

func newApplyCommand() *cobra.Command {
	var (
		profile   string
		yipBinary string
	)

	cmd := &cobra.Command{
		Use:   "apply <baseline>",
		Short: "Apply STIG remediation with Yip",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}
			files, err := resolved.RemediationFiles()
			if err != nil {
				return err
			}

			result, err := yip.New(yipBinary).Apply(cmd.Context(), remediation.Request{
				Baseline: args[0],
				Profile:  profile,
				Stage:    "stig",
				Files:    files,
			})
			if result.Stdout != "" {
				fmt.Fprint(cmd.OutOrStdout(), result.Stdout)
			}
			if result.Stderr != "" {
				fmt.Fprint(cmd.ErrOrStderr(), result.Stderr)
			}
			return err
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "default", "system profile")
	cmd.Flags().StringVar(&yipBinary, "yip-binary", "yip", "path to the Yip executable")
	return cmd
}
