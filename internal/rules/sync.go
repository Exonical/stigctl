package rules

import (
	"fmt"
	"os"

	"github.com/Exonical/stigctl/internal/xccdf"
	"gopkg.in/yaml.v3"
)

func Sync(existing Document, benchmark xccdf.Benchmark) Document {
	if existing.SchemaVersion == 0 {
		existing.SchemaVersion = 1
	}
	if existing.Rules == nil {
		existing.Rules = map[string]Rule{}
	}

	next := make(map[string]Rule, len(benchmark.Rules))
	for _, source := range benchmark.Rules {
		rule, ok := existing.Rules[source.VulnID]
		if !ok {
			rule.Status = StatusManual
		}
		rule.VulnID = source.VulnID
		rule.Title = source.Title
		rule.RuleID = source.RuleID
		rule.Severity = source.Severity
		next[source.VulnID] = rule
	}
	existing.Rules = next
	return existing
}

func Save(path string, doc Document) error {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write rules: %w", err)
	}
	return nil
}
