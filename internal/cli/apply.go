package cli

import (
	"fmt"
	"sort"
	"time"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/host"
	"github.com/Exonical/stigctl/internal/remediation"
	"github.com/Exonical/stigctl/internal/remediation/yip"
	"github.com/Exonical/stigctl/internal/rules"
	"github.com/spf13/cobra"
)

func newApplyCommand() *cobra.Command {
	var (
		profile          string
		yipBinary        string
		ignoreExceptions bool
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

			filtered := yip.FilterResult{Files: files, Cleanup: func() {}}
			if !ignoreExceptions {
				ruleDoc, err := rules.Load(resolved.RulesFile())
				if err != nil {
					return err
				}
				exceptionDoc, err := exceptions.Load(resolved.ExceptionsFile())
				if err != nil {
					return err
				}

				facts := host.Detect()
				skipSteps := map[string]struct{}{}
				var skippedIDs []string
				for id, exception := range exceptionDoc.Exceptions {
					if !exception.Applies(exceptions.Context{
						Profile: profile,
						Host:    facts.Hostname,
						Now:     time.Now(),
					}) {
						continue
					}

					rule, ok := ruleDoc.Rules[id]
					if !ok {
						return fmt.Errorf("active exception %s has no matching rules.yaml entry", id)
					}
					if rule.Remediation.File == "" {
						continue
					}
					if rule.Remediation.Step == "" {
						return fmt.Errorf("active exception %s has remediation file %s but no remediation.step mapping", id, rule.Remediation.File)
					}

					skipSteps[rule.Remediation.Step] = struct{}{}
					skippedIDs = append(skippedIDs, id)
				}

				filtered, err = yip.FilterFiles(files, "stig", skipSteps)
				if err != nil {
					return err
				}
				sort.Strings(skippedIDs)
				for _, id := range skippedIDs {
					fmt.Fprintf(cmd.OutOrStdout(), "skipping excepted remediation %s\n", id)
				}
			}
			defer filtered.Cleanup()

			result, err := yip.New(yipBinary).Apply(cmd.Context(), remediation.Request{
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
	cmd.Flags().StringVar(&yipBinary, "yip-binary", "yip", "path to the Yip executable")
	cmd.Flags().BoolVar(&ignoreExceptions, "ignore-exceptions", false, "apply remediation even when an approved exception applies")
	return cmd
}
