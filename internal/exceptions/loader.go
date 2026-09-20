package exceptions

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

func Load(path string) (Document, error) {
	doc, _, err := LoadWithWarnings(path, time.Now())
	return doc, err
}

func LoadWithWarnings(path string, now time.Time) (Document, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, nil, fmt.Errorf("read exceptions: %w", err)
	}

	var doc Document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Document{}, nil, fmt.Errorf("parse exceptions: %w", err)
	}
	if doc.Exceptions == nil {
		doc.Exceptions = map[string]Exception{}
	}

	for id, exception := range doc.Exceptions {
		exception.VulnID = id
		doc.Exceptions[id] = exception
	}

	warnings, err := Validate(doc, now)
	return doc, warnings, err
}
