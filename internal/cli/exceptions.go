package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/spf13/cobra"
)

func newExceptionsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exceptions",
		Short: "Inspect STIG exceptions",
	}

	var profile string
	listCmd := &cobra.Command{
		Use:   "list <baseline>",
		Short: "List exceptions by profile scope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if profile != "" {
				if err := validateProfile(profile); err != nil {
					return err
				}
			}
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}
			doc, err := exceptions.Load(resolved.ExceptionsFile())
			if err != nil {
				return err
			}
			for _, row := range exceptionListRows(doc, profile) {
				fmt.Fprintf(cmd.OutOrStdout(), "%-24s %-14s %-15s %s\n", row.Scope, row.VulnID, row.Status, row.Reason)
			}
			return nil
		},
	}
	listCmd.Flags().StringVar(&profile, "profile", "", "show exceptions that apply to this profile")

	cmd.AddCommand(
		listCmd,
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

type exceptionListRow struct {
	Scope  string
	VulnID string
	Status string
	Reason string
}

func exceptionListRows(doc exceptions.Document, profile string) []exceptionListRow {
	rows := make([]exceptionListRow, 0, len(doc.Exceptions))
	for id, exception := range doc.Exceptions {
		for _, scope := range exceptionScopes(exception, profile) {
			rows = append(rows, exceptionListRow{
				Scope: scope, VulnID: id, Status: exception.Status,
				Reason: exception.Justification.Reason,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		leftScope := strings.ToLower(rows[i].Scope)
		rightScope := strings.ToLower(rows[j].Scope)
		if leftScope != rightScope {
			return leftScope < rightScope
		}
		return rows[i].VulnID < rows[j].VulnID
	})
	return rows
}

func exceptionScopes(exception exceptions.Exception, profile string) []string {
	if exception.Scope.All {
		return []string{"all"}
	}
	var scopes []string
	seen := map[string]struct{}{}
	add := func(scope string) {
		key := strings.ToLower(scope)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		scopes = append(scopes, scope)
	}
	for _, candidate := range exception.Scope.Profiles {
		if profile == "" || strings.EqualFold(candidate, profile) {
			add(candidate)
		}
	}
	if profile != "" {
		return scopes
	}
	for _, host := range exception.Scope.Hosts {
		add("host:" + host)
	}
	if len(scopes) == 0 {
		return []string{"unscoped"}
	}
	return scopes
}
