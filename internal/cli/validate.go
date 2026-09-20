package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/host"
	"github.com/Exonical/stigctl/internal/policy"
	"github.com/Exonical/stigctl/internal/rules"
	"github.com/Exonical/stigctl/internal/validation"
	"github.com/Exonical/stigctl/internal/validation/goss"
	"github.com/spf13/cobra"
)

func newValidateCommand() *cobra.Command {
	var (
		profile        string
		failOnFindings bool
	)

	cmd := &cobra.Command{
		Use:   "validate <baseline>",
		Short: "Validate a STIG baseline with Goss",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateProfile(profile); err != nil {
				return err
			}
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}
			gossFile, err := resolved.GossFile()
			if err != nil {
				return err
			}

			ruleDoc, err := rules.Load(resolved.RulesFile())
			if err != nil {
				return err
			}
			exceptionDoc, err := exceptions.Load(resolved.ExceptionsFile())
			if err != nil {
				return err
			}
			facts := host.Detect()

			varsFile, cleanup, err := writeEffectiveGossVars(ruleDoc, exceptionDoc, profile, facts.Hostname, filepath.Join(filepath.Dir(gossFile), "stig-check.sh"))
			if err != nil {
				return err
			}
			defer cleanup()

			scanned, err := goss.New().Validate(cmd.Context(), validation.Request{
				Baseline: args[0],
				Profile:  profile,
				GossFile: gossFile,
				Vars:     []string{varsFile},
				Package:  "rpm",
			})
			if err != nil {
				return err
			}

			merged := policy.Merge(ruleDoc, exceptionDoc, scanned, policy.Context{
				Profile:  profile,
				Hostname: facts.Hostname,
				Now:      time.Now(),
			})

			for _, result := range merged {
				fmt.Fprintf(cmd.OutOrStdout(), "%-14s %-18s %s\n", result.VulnID, result.Status, result.Title)
			}
			fmt.Fprintln(cmd.OutOrStdout(), policy.Summary(merged))

			if failOnFindings && policy.HasFailures(merged) {
				return fmt.Errorf("STIG validation contains open findings or validation errors")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "default", "system profile")
	cmd.Flags().BoolVar(&failOnFindings, "fail-on-findings", true, "exit non-zero when open findings or validation errors exist")
	return cmd
}
