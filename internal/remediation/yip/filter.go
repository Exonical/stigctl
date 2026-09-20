package yip

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type FilterResult struct {
	Files   []string
	Cleanup func()
}

type Step struct {
	Name string
	File string
}

func ListSteps(files []string, stage string) ([]Step, error) {
	var out []Step
	for _, source := range files {
		_, steps, err := loadStage(source, stage)
		if err != nil {
			return nil, err
		}
		for _, raw := range steps {
			step, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name, _ := step["name"].(string)
			out = append(out, Step{Name: name, File: source})
		}
	}
	return out, nil
}

func FilterFiles(files []string, stage string, skipSteps map[string]struct{}) (FilterResult, error) {
	if len(skipSteps) == 0 {
		return FilterResult{Files: files, Cleanup: func() {}}, nil
	}

	dir, err := os.MkdirTemp("", "stigctl-yip-*")
	if err != nil {
		return FilterResult{}, fmt.Errorf("create Yip temporary directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	out := make([]string, 0, len(files))
	found := make(map[string]struct{}, len(skipSteps))
	for _, source := range files {
		doc, steps, err := loadStage(source, stage)
		if err != nil {
			cleanup()
			return FilterResult{}, err
		}

		stages, _ := doc["stages"].(map[string]any)
		if len(steps) > 0 {
			filtered := make([]any, 0, len(steps))
			for _, raw := range steps {
				step, ok := raw.(map[string]any)
				if !ok {
					filtered = append(filtered, raw)
					continue
				}
				name, _ := step["name"].(string)
				if _, skip := skipSteps[name]; skip {
					found[name] = struct{}{}
					continue
				}
				filtered = append(filtered, raw)
			}
			stages[stage] = filtered
		}

		rendered, err := yaml.Marshal(doc)
		if err != nil {
			cleanup()
			return FilterResult{}, fmt.Errorf("render filtered Yip file %s: %w", source, err)
		}
		target := filepath.Join(dir, filepath.Base(source))
		if err := os.WriteFile(target, rendered, 0o600); err != nil {
			cleanup()
			return FilterResult{}, fmt.Errorf("write filtered Yip file %s: %w", target, err)
		}
		out = append(out, target)
	}

	for name := range skipSteps {
		if _, ok := found[name]; !ok {
			cleanup()
			return FilterResult{}, fmt.Errorf("excepted Yip remediation step %q was not found", name)
		}
	}

	return FilterResult{Files: out, Cleanup: cleanup}, nil
}

func loadStage(source, stage string) (map[string]any, []any, error) {
	data, err := os.ReadFile(source)
	if err != nil {
		return nil, nil, fmt.Errorf("read Yip file %s: %w", source, err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse Yip file %s: %w", source, err)
	}
	stages, _ := doc["stages"].(map[string]any)
	steps, _ := stages[stage].([]any)
	return doc, steps, nil
}
