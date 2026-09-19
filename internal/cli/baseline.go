package cli

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Exonical/stigctl/internal/baseline"
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
			defer file.Close()

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
			defer reader.Close()

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
			defer in.Close()

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
				out.Close()
				return fmt.Errorf("copy XCCDF: %w", err)
			}
			if err := out.Close(); err != nil {
				return fmt.Errorf("close XCCDF destination: %w", err)
			}

			check, err := os.Open(destination)
			if err != nil {
				return fmt.Errorf("reopen imported XCCDF: %w", err)
			}
			benchmark, err := xccdf.Parse(check)
			check.Close()
			if err != nil {
				return fmt.Errorf("validate imported XCCDF: %w", err)
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
