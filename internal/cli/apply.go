//go:build linux

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/host"
	"github.com/Exonical/stigctl/internal/policy"
	"github.com/Exonical/stigctl/internal/remediation"
	"github.com/Exonical/stigctl/internal/remediation/yip"
	"github.com/Exonical/stigctl/internal/rules"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var stdinIsTerminal = func() bool {
	fd := os.Stdin.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func newApplyCommand() *cobra.Command {
	var (
		profile          string
		ignoreExceptions bool
		dryRun           bool
		yes              bool
		selectedRules    []string
	)

	cmd := &cobra.Command{
		Use:   "apply <baseline>",
		Short: "Apply STIG remediation with Yip",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateProfile(profile); err != nil {
				return err
			}
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}
			files, err := resolved.RemediationFiles()
			if err != nil {
				return err
			}
			ruleDoc, err := rules.Load(resolved.RulesFile())
			if err != nil {
				return err
			}

			selected := make(map[string]struct{}, len(selectedRules))
			for _, id := range selectedRules {
				rule, ok := ruleDoc.Rules[id]
				if !ok {
					return fmt.Errorf("unknown rule %s", id)
				}
				if rule.Remediation.File == "" {
					return fmt.Errorf("rule %s has no remediation mapping", id)
				}
				if rule.Remediation.Step == "" {
					return fmt.Errorf("rule %s has remediation file %s but no remediation.step mapping", id, rule.Remediation.File)
				}
				selected[id] = struct{}{}
			}

			facts := host.Detect()
			enabled := map[string]bool{}
			if !ignoreExceptions {
				exceptionDoc, err := exceptions.Load(resolved.ExceptionsFile())
				if err != nil {
					return err
				}
				enabled = policy.EnabledRules(ruleDoc, exceptionDoc, policy.DefaultContext(profile, facts.Hostname))
			}

			skipSteps := map[string]struct{}{}
			var skippedIDs []string
			for id, rule := range ruleDoc.Rules {
				if rule.Remediation.File == "" {
					continue
				}
				if rule.Remediation.Step == "" {
					return fmt.Errorf("rule %s has remediation file %s but no remediation.step mapping", id, rule.Remediation.File)
				}
				if len(selected) > 0 {
					if _, ok := selected[id]; !ok {
						skipSteps[rule.Remediation.Step] = struct{}{}
						continue
					}
				}
				if !ignoreExceptions && !enabled[id] {
					skipSteps[rule.Remediation.Step] = struct{}{}
					skippedIDs = append(skippedIDs, id)
				}
			}

			allSteps, err := yip.ListSteps(files, "stig")
			if err != nil {
				return err
			}
			plannedSteps := make([]yip.Step, 0, len(allSteps))
			for _, step := range allSteps {
				if _, skip := skipSteps[step.Name]; !skip {
					plannedSteps = append(plannedSteps, step)
				}
			}

			filtered, err := yip.FilterFiles(files, "stig", skipSteps)
			if err != nil {
				return err
			}
			defer filtered.Cleanup()

			sort.Strings(skippedIDs)
			for _, id := range skippedIDs {
				fmt.Fprintf(cmd.OutOrStdout(), "skipping remediation %s due to effective policy\n", id)
			}

			if dryRun {
				fmt.Fprintf(
					cmd.OutOrStdout(),
					"would apply %d remediation step(s) from %s (profile %s):\n",
					len(plannedSteps),
					args[0],
					profile,
				)
				for _, step := range plannedSteps {
					rel, err := filepath.Rel(resolved.Path, step.File)
					if err != nil {
						return fmt.Errorf("resolve remediation path for %s: %w", step.Name, err)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "  %s  %s\n", step.Name, filepath.ToSlash(rel))
				}
				if len(skippedIDs) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "skipped by policy: %d\n", len(skippedIDs))
				}
				return nil
			}

			if !yes && stdinIsTerminal() {
				fmt.Fprintf(
					cmd.ErrOrStderr(),
					"apply %d remediation step(s) from %s to %s (profile %s)? [y/N] ",
					len(plannedSteps),
					args[0],
					facts.Hostname,
					profile,
				)
				answer, readErr := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				if readErr != nil && !errors.Is(readErr, io.EOF) {
					return fmt.Errorf("read apply confirmation: %w", readErr)
				}
				answer = strings.TrimSpace(answer)
				if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
					return fmt.Errorf("apply cancelled")
				}
			}

			result, err := yip.New().Apply(cmd.Context(), remediation.Request{
				Baseline: args[0],
				Profile:  profile,
				Stage:    "stig",
				Files:    filtered.Files,
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
	cmd.Flags().BoolVar(&ignoreExceptions, "ignore-exceptions", false, "apply remediation even when an approved exception applies")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the remediation plan without applying it")
	cmd.Flags().StringSliceVar(&selectedRules, "rules", nil, "apply only the listed V-IDs")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "apply without confirmation")
	return cmd
}
