package cli

import (
	"encoding/json"
	"fmt"

	stigprofile "github.com/Exonical/stigctl/internal/profile"
	"github.com/spf13/cobra"
)

func newProfileCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Inspect system applicability profiles",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List profiles",
			RunE: func(cmd *cobra.Command, args []string) error {
				items, err := stigprofile.NewStore(contentRoot).List()
				if err != nil {
					return err
				}
				for _, item := range items {
					fmt.Fprintf(cmd.OutOrStdout(), "%-28s %s\n", item.Profile.ID, item.Profile.Name)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "show <profile>",
			Short: "Show profile metadata",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				item, err := stigprofile.NewStore(contentRoot).Resolve(args[0])
				if err != nil {
					return err
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(item)
			},
		},
	)

	return cmd
}
