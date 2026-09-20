package baseline

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Resolved struct {
	Ref      string
	Path     string
	Manifest Manifest
}

type Store struct {
	Root string
}

func NewStore(root string) Store {
	if root == "" {
		root = "."
	}
	return Store{Root: root}
}

func (s Store) Resolve(ref string) (Resolved, error) {
	product, release, ok := strings.Cut(ref, ":")
	if !ok || product == "" || release == "" {
		return Resolved{}, fmt.Errorf("invalid baseline %q: expected <product>:<release>, for example rhel9:v2r9", ref)
	}

	path := filepath.Join(s.Root, "stig", product, release)
	manifestPath := filepath.Join(path, "manifest.yaml")
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve baseline %q: %w", ref, err)
	}

	return Resolved{Ref: ref, Path: path, Manifest: manifest}, nil
}

func (s Store) List() ([]Resolved, error) {
	pattern := filepath.Join(s.Root, "stig", "*", "*", "manifest.yaml")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob baselines: %w", err)
	}

	out := make([]Resolved, 0, len(paths))
	for _, manifestPath := range paths {
		manifest, err := LoadManifest(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", manifestPath, err)
		}

		releaseDir := filepath.Dir(manifestPath)
		release := filepath.Base(releaseDir)
		product := filepath.Base(filepath.Dir(releaseDir))
		out = append(out, Resolved{
			Ref:      product + ":" + release,
			Path:     releaseDir,
			Manifest: manifest,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, nil
}

func (r Resolved) RemediationFiles() ([]string, error) {
	pattern := filepath.Join(r.Path, "remediation", "[0-9][0-9]-*.yaml")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob remediation files: %w", err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no remediation files found under %s", filepath.Join(r.Path, "remediation"))
	}
	return files, nil
}

func (r Resolved) GossFile() (string, error) {
	path := filepath.Join(r.Path, "validation", "goss.yaml")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("goss validation file: %w", err)
	}
	return path, nil
}

func (r Resolved) RulesFile() string {
	return filepath.Join(r.Path, "rules.yaml")
}

func (r Resolved) ExceptionsFile() string {
	return filepath.Join(r.Path, "exceptions.yaml")
}

func (r Resolved) XCCDFFile() (string, error) {
	files, err := filepath.Glob(filepath.Join(r.Path, "source", "*.xml"))
	if err != nil {
		return "", fmt.Errorf("glob XCCDF source: %w", err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return "", fmt.Errorf("no XCCDF source XML found under %s", filepath.Join(r.Path, "source"))
	}
	return files[0], nil
}

func (r Resolved) CKLBTemplateFile() (string, error) {
	files, err := filepath.Glob(filepath.Join(r.Path, "source", "*.cklb"))
	if err != nil {
		return "", fmt.Errorf("glob CKLB template: %w", err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return "", nil
	}
	if len(files) > 1 {
		return "", fmt.Errorf("multiple CKLB templates found under %s", filepath.Join(r.Path, "source"))
	}
	return files[0], nil
}
