package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/rules"
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
			fmt.Fprintf(cmd.OutOrStdout(), "%-24s %-14s %-15s %s\n", "SCOPE", "VULN ID", "STATUS", "REASON")
			for _, row := range exceptionListRows(doc, profile) {
				fmt.Fprintf(cmd.OutOrStdout(), "%-24s %-14s %-15s %s\n", row.Scope, row.VulnID, row.Status, row.Reason)
			}
			return nil
		},
	}
	listCmd.Flags().StringVar(&profile, "profile", "", "show exceptions that apply to this profile")

	cmd.AddCommand(
		listCmd,
		newExceptionsLintCommand(),
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

func newExceptionsLintCommand() *cobra.Command {
	var strict bool
	cmd := &cobra.Command{
		Use:   "lint <baseline>",
		Short: "Validate baseline exceptions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}
			ruleDoc, err := rules.Load(resolved.RulesFile())
			if err != nil {
				return err
			}
			doc, warnings, validationErr := exceptions.LoadWithWarnings(resolved.ExceptionsFile(), time.Now())
			for _, warning := range warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), warning)
			}
			referenceErr := exceptions.CheckRuleReferences(doc, ruleDoc)
			if err := errors.Join(validationErr, referenceErr); err != nil {
				return err
			}
			if strict && len(warnings) > 0 {
				return fmt.Errorf("exceptions lint found %d warning(s)", len(warnings))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "exceptions ok: %d exceptions, %d warnings\n", len(doc.Exceptions), len(warnings))
			return nil
		},
	}
	cmd.Flags().BoolVar(&strict, "strict", false, "treat warnings as errors")
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
