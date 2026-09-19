package cli

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/spf13/cobra"
)

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
				resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
				if err != nil {
					return err
				}
				doc, err := exceptions.Load(resolved.ExceptionsFile())
				if err != nil {
					return err
				}
				ids := make([]string, 0, len(doc.Exceptions))
				for id := range doc.Exceptions {
					ids = append(ids, id)
				}
				sort.Strings(ids)
				for _, id := range ids {
					exception := doc.Exceptions[id]
					fmt.Fprintf(cmd.OutOrStdout(), "%-14s %-12s %s\n", id, exception.Status, exception.Justification.Reason)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "show <baseline> <vuln-id>",
			Short: "Show an exception",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
				if err != nil {
					return err
				}
				doc, err := exceptions.Load(resolved.ExceptionsFile())
				if err != nil {
					return err
				}
				exception, ok := doc.Exceptions[args[1]]
				if !ok {
					return fmt.Errorf("exception %s not found", args[1])
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(exception)
			},
		},
	)

	return cmd
}
