package exceptions

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("read exceptions: %w", err)
	}

	var doc Document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Document{}, fmt.Errorf("parse exceptions: %w", err)
	}
	if doc.Exceptions == nil {
		doc.Exceptions = map[string]Exception{}
	}

	for id, exception := range doc.Exceptions {
		exception.VulnID = id
		doc.Exceptions[id] = exception
	}

	return doc, nil
}
