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
		data, err := os.ReadFile(source)
		if err != nil {
			cleanup()
			return FilterResult{}, fmt.Errorf("read Yip file %s: %w", source, err)
		}

		var doc map[string]any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			cleanup()
			return FilterResult{}, fmt.Errorf("parse Yip file %s: %w", source, err)
		}

		stages, _ := doc["stages"].(map[string]any)
		steps, _ := stages[stage].([]any)
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
