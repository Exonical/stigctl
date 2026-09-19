package rules

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("read rules: %w", err)
	}

	var doc Document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Document{}, fmt.Errorf("parse rules: %w", err)
	}
	if doc.Rules == nil {
		doc.Rules = map[string]Rule{}
	}

	for id, rule := range doc.Rules {
		rule.VulnID = id
		doc.Rules[id] = rule
	}

	return doc, nil
}
