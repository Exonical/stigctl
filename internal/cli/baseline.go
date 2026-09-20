package cli

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Exonical/stigctl/internal/baseline"
	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/export/cklb"
	"github.com/Exonical/stigctl/internal/rules"
	"github.com/Exonical/stigctl/internal/xccdf"
	"github.com/spf13/cobra"
)

func newBaselineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Inspect and maintain STIG baselines",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List available baselines",
			RunE: func(cmd *cobra.Command, args []string) error {
				items, err := baseline.NewStore(contentRoot).List()
				if err != nil {
					return err
				}
				for _, item := range items {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"%-16s %s (implementation %d) [%s]\n",
						item.Ref,
						item.Manifest.Baseline.DisplayName,
						item.Manifest.Implementation.Revision,
						item.Manifest.Status,
					)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "show <baseline>",
			Short: "Show baseline metadata",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				item, err := baseline.NewStore(contentRoot).Resolve(args[0])
				if err != nil {
					return err
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(item.Manifest)
			},
		},
		newBaselineSyncCommand(),
		newBaselineImportCommand(),
		newBaselineImportCKLBCommand(),
		newBaselineVerifyCommand(),
		newBaselineCoverageCommand(),
	)

	return cmd
}

func newBaselineSyncCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "sync <baseline>",
		Short: "Refresh rules.yaml metadata from the authoritative XCCDF",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}
			xccdfPath, err := resolved.XCCDFFile()
			if err != nil {
				return err
			}
			file, err := os.Open(xccdfPath)
			if err != nil {
				return fmt.Errorf("open XCCDF source: %w", err)
			}
			defer func() { _ = file.Close() }()

			benchmark, err := xccdf.Parse(file)
			if err != nil {
				return err
			}
			existing, err := rules.Load(resolved.RulesFile())
			if err != nil {
				return err
			}
			synced := rules.Sync(existing, benchmark)
			if err := rules.Save(resolved.RulesFile(), synced); err != nil {
				return err
			}

			fmt.Fprintf(
				cmd.OutOrStdout(),
				"synced %d rules from %s into %s\n",
				len(benchmark.Rules),
				xccdfPath,
				resolved.RulesFile(),
			)
			return nil
		},
	}
}

func newBaselineImportCommand() *cobra.Command {
	var syncRules bool

	cmd := &cobra.Command{
		Use:   "import <baseline> <stig-zip>",
		Short: "Import the authoritative DISA XCCDF from a STIG release ZIP",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}

			reader, err := zip.OpenReader(args[1])
			if err != nil {
				return fmt.Errorf("open STIG ZIP: %w", err)
			}
			defer func() { _ = reader.Close() }()

			var source *zip.File
			for _, entry := range reader.File {
				name := strings.ToLower(filepath.Base(entry.Name))
				if strings.HasSuffix(name, "-xccdf.xml") || strings.HasSuffix(name, "_xccdf.xml") {
					if source != nil {
						return fmt.Errorf("STIG ZIP contains multiple XCCDF candidates: %s and %s", source.Name, entry.Name)
					}
					source = entry
				}
			}
			if source == nil {
				return fmt.Errorf("STIG ZIP contains no *-xccdf.xml file")
			}

			in, err := source.Open()
			if err != nil {
				return fmt.Errorf("open XCCDF in ZIP: %w", err)
			}
			defer func() { _ = in.Close() }()

			sourceDir := filepath.Join(resolved.Path, "source")
			if err := os.MkdirAll(sourceDir, 0o755); err != nil {
				return fmt.Errorf("create source directory: %w", err)
			}

			destination := filepath.Join(sourceDir, filepath.Base(source.Name))
			out, err := os.Create(destination)
			if err != nil {
				return fmt.Errorf("create XCCDF destination: %w", err)
			}
			if _, err := io.Copy(out, in); err != nil {
				copyErr := fmt.Errorf("copy XCCDF: %w", err)
				if closeErr := out.Close(); closeErr != nil {
					return errors.Join(copyErr, fmt.Errorf("close XCCDF destination: %w", closeErr))
				}
				return copyErr
			}
			if err := out.Close(); err != nil {
				return fmt.Errorf("close XCCDF destination: %w", err)
			}

			check, err := os.Open(destination)
			if err != nil {
				return fmt.Errorf("reopen imported XCCDF: %w", err)
			}
			benchmark, parseErr := xccdf.Parse(check)
			closeErr := check.Close()
			if parseErr != nil {
				return fmt.Errorf("validate imported XCCDF: %w", parseErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close imported XCCDF: %w", closeErr)
			}
			if benchmark.Version != fmt.Sprint(resolved.Manifest.Baseline.Version) {
				return fmt.Errorf(
					"imported XCCDF version %q does not match manifest version %d",
					benchmark.Version,
					resolved.Manifest.Baseline.Version,
				)
			}

			if syncRules {
				existing, err := rules.Load(resolved.RulesFile())
				if err != nil {
					return err
				}
				synced := rules.Sync(existing, benchmark)
				if err := rules.Save(resolved.RulesFile(), synced); err != nil {
					return err
				}
			}

			fmt.Fprintf(
				cmd.OutOrStdout(),
				"imported %s (%d rules, %s) to %s\n",
				benchmark.Title,
				len(benchmark.Rules),
				benchmark.ReleaseInfo,
				destination,
			)
			if syncRules {
				fmt.Fprintf(cmd.OutOrStdout(), "synced rules.yaml from imported XCCDF\n")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&syncRules, "sync-rules", true, "refresh rules.yaml from the imported XCCDF")
	return cmd
}

func newBaselineImportCKLBCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "import-cklb <baseline> <cklb-file>",
		Short: "Import a STIG Viewer 3 CKLB template for exact metadata preservation",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}

			template, err := cklb.LoadFile(args[1])
			if err != nil {
				return err
			}
			if len(template.STIGs) != 1 {
				return fmt.Errorf("expected exactly one STIG in CKLB template, got %d", len(template.STIGs))
			}

			stig := template.STIGs[0]
			if stig.STIGID != resolved.Manifest.Baseline.Identifier {
				return fmt.Errorf(
					"CKLB STIG ID %q does not match manifest identifier %q",
					stig.STIGID,
					resolved.Manifest.Baseline.Identifier,
				)
			}
			if stig.Version != fmt.Sprint(resolved.Manifest.Baseline.Version) {
				return fmt.Errorf(
					"CKLB version %q does not match manifest version %d",
					stig.Version,
					resolved.Manifest.Baseline.Version,
				)
			}

			if xccdfPath, err := resolved.XCCDFFile(); err == nil {
				source, err := os.Open(xccdfPath)
				if err != nil {
					return fmt.Errorf("open XCCDF source: %w", err)
				}
				benchmark, parseErr := xccdf.Parse(source)
				closeErr := source.Close()
				if parseErr != nil {
					return parseErr
				}
				if closeErr != nil {
					return fmt.Errorf("close XCCDF source: %w", closeErr)
				}
				mismatches := cklb.CompareBenchmark(template, benchmark)
				if len(mismatches) > 0 {
					return fmt.Errorf("CKLB template does not align with XCCDF: %d metadata mismatch(es)", len(mismatches))
				}
			}

			template, err = cklb.SanitizeTemplate(template, args[0])
			if err != nil {
				return err
			}

			sourceDir := filepath.Join(resolved.Path, "source")
			if err := os.MkdirAll(sourceDir, 0o755); err != nil {
				return fmt.Errorf("create source directory: %w", err)
			}
			destination := filepath.Join(sourceDir, "template.cklb")

			dst, err := os.Create(destination)
			if err != nil {
				return fmt.Errorf("create CKLB destination: %w", err)
			}
			if err := cklb.Write(dst, template); err != nil {
				if closeErr := dst.Close(); closeErr != nil {
					return errors.Join(err, fmt.Errorf("close CKLB destination: %w", closeErr))
				}
				return err
			}
			if err := dst.Close(); err != nil {
				return fmt.Errorf("close CKLB destination: %w", err)
			}

			fmt.Fprintf(
				cmd.OutOrStdout(),
				"imported CKLB template %s (%d rules) to %s\n",
				stig.DisplayName,
				len(stig.Rules),
				destination,
			)
			return nil
		},
	}
}

func newBaselineVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <baseline>",
		Short: "Verify XCCDF, rules, and optional CKLB template alignment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}

			xccdfPath, err := resolved.XCCDFFile()
			if err != nil {
				return err
			}
			source, err := os.Open(xccdfPath)
			if err != nil {
				return fmt.Errorf("open XCCDF source: %w", err)
			}
			benchmark, parseErr := xccdf.Parse(source)
			closeErr := source.Close()
			if parseErr != nil {
				return parseErr
			}
			if closeErr != nil {
				return fmt.Errorf("close XCCDF source: %w", closeErr)
			}

			ruleDoc, err := rules.Load(resolved.RulesFile())
			if err != nil {
				return err
			}
			exceptionDoc, warnings, err := exceptions.LoadWithWarnings(resolved.ExceptionsFile(), time.Now())
			for _, warning := range warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), warning)
			}
			if err != nil {
				return err
			}
			if err := exceptions.CheckRuleReferences(exceptionDoc, ruleDoc); err != nil {
				return err
			}
			if len(ruleDoc.Rules) != len(benchmark.Rules) {
				return fmt.Errorf(
					"rules.yaml contains %d rules but XCCDF contains %d",
					len(ruleDoc.Rules),
					len(benchmark.Rules),
				)
			}

			for id, rule := range ruleDoc.Rules {
				if rule.Status == rules.StatusAutomated || rule.Status == rules.StatusTailored {
					if rule.Validation.File == "" || rule.Validation.Type == "" || rule.Validation.Resource == "" || rule.Validation.Test == "" {
						return fmt.Errorf("automated rule %s has incomplete validation mapping", id)
					}
					validationPath := filepath.Join(resolved.Path, rule.Validation.File)
					data, err := os.ReadFile(validationPath)
					if err != nil {
						return fmt.Errorf("read validation mapping for %s: %w", id, err)
					}
					if !strings.Contains(string(data), rule.Validation.Test) {
						return fmt.Errorf(
							"validation mapping for %s references missing test %q in %s",
							id,
							rule.Validation.Test,
							rule.Validation.File,
						)
					}
				}

				if rule.Remediation.File != "" {
					if rule.Remediation.Step == "" {
						return fmt.Errorf("rule %s has remediation file %s but no remediation step", id, rule.Remediation.File)
					}
					remediationPath := filepath.Join(resolved.Path, rule.Remediation.File)
					data, err := os.ReadFile(remediationPath)
					if err != nil {
						return fmt.Errorf("read remediation mapping for %s: %w", id, err)
					}
					if !strings.Contains(string(data), "name: "+rule.Remediation.Step) {
						return fmt.Errorf(
							"remediation mapping for %s references missing step %q in %s",
							id,
							rule.Remediation.Step,
							rule.Remediation.File,
						)
					}
				}
			}

			templatePath, err := resolved.CKLBTemplateFile()
			if err != nil {
				return err
			}
			if templatePath != "" {
				template, err := cklb.LoadFile(templatePath)
				if err != nil {
					return err
				}
				mismatches := cklb.CompareBenchmark(template, benchmark)
				if len(mismatches) > 0 {
					limit := len(mismatches)
					if limit > 20 {
						limit = 20
					}
					for _, mismatch := range mismatches[:limit] {
						fmt.Fprintf(
							cmd.ErrOrStderr(),
							"%s %s: XCCDF=%q CKLB=%q\n",
							mismatch.VulnID,
							mismatch.Field,
							mismatch.Want,
							mismatch.Got,
						)
					}
					return fmt.Errorf(
						"CKLB template differs from XCCDF in %d field(s)",
						len(mismatches),
					)
				}
			}

			fmt.Fprintf(
				cmd.OutOrStdout(),
				"verified %s: %d rules, %s",
				args[0],
				len(benchmark.Rules),
				benchmark.ReleaseInfo,
			)
			if templatePath != "" {
				fmt.Fprintf(cmd.OutOrStdout(), ", CKLB template aligned")
			}
			fmt.Fprintln(cmd.OutOrStdout())
			return nil
		},
	}
}

func newBaselineCoverageCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "coverage <baseline>",
		Short: "Show implementation coverage for a STIG baseline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := baseline.NewStore(contentRoot).Resolve(args[0])
			if err != nil {
				return err
			}
			doc, err := rules.Load(resolved.RulesFile())
			if err != nil {
				return err
			}

			statusCounts := map[rules.Status]int{}
			moduleCounts := map[string]int{}
			for _, rule := range doc.Rules {
				statusCounts[rule.Status]++
				if rule.Remediation.File != "" {
					moduleCounts[rule.Remediation.File]++
				}
			}

			total := len(doc.Rules)
			automated := statusCounts[rules.StatusAutomated] + statusCounts[rules.StatusTailored]
			coverage := 0.0
			if total > 0 {
				coverage = float64(automated) / float64(total) * 100
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s implementation coverage\n", args[0])
			fmt.Fprintf(cmd.OutOrStdout(), "  total:          %d\n", total)
			fmt.Fprintf(cmd.OutOrStdout(), "  automated:      %d\n", statusCounts[rules.StatusAutomated])
			fmt.Fprintf(cmd.OutOrStdout(), "  tailored:       %d\n", statusCounts[rules.StatusTailored])
			fmt.Fprintf(cmd.OutOrStdout(), "  manual:         %d\n", statusCounts[rules.StatusManual])
			fmt.Fprintf(cmd.OutOrStdout(), "  not applicable: %d\n", statusCounts[rules.StatusNotApplicable])
			fmt.Fprintf(cmd.OutOrStdout(), "  coverage:       %.1f%%\n", coverage)

			if len(moduleCounts) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "  modules:")
				names := make([]string, 0, len(moduleCounts))
				for name := range moduleCounts {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					fmt.Fprintf(cmd.OutOrStdout(), "    %-32s %d\n", name, moduleCounts[name])
				}
			}
			return nil
		},
	}
}
