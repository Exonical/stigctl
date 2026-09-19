package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

type Store struct {
	Root string
}

func NewStore(root string) Store {
	if root == "" {
		root = "."
	}
	return Store{Root: root}
}

func (s Store) Resolve(id string) (Document, error) {
	path := filepath.Join(s.Root, "profiles", id+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("profile %q: %w", id, err)
	}
	var doc Document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Document{}, fmt.Errorf("parse profile %q: %w", id, err)
	}
	if doc.Profile.ID == "" {
		return Document{}, fmt.Errorf("profile %q has no profile.id", id)
	}
	if doc.Profile.ID != id {
		return Document{}, fmt.Errorf("profile file %q declares id %q", id, doc.Profile.ID)
	}
	return doc, nil
}

func (s Store) List() ([]Document, error) {
	paths, err := filepath.Glob(filepath.Join(s.Root, "profiles", "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	sort.Strings(paths)
	out := make([]Document, 0, len(paths))
	for _, path := range paths {
		id := filepath.Base(path[:len(path)-len(filepath.Ext(path))])
		doc, err := s.Resolve(id)
		if err != nil {
			return nil, err
		}
		out = append(out, doc)
	}
	return out, nil
}
