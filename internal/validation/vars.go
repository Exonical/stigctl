package validation

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Vars struct {
	Profile      string          `yaml:"profile"`
	Hostname     string          `yaml:"hostname"`
	CheckScript  string          `yaml:"check_script,omitempty"`
	EnabledRules map[string]bool `yaml:"enabled_rules"`
}

func WriteVars(path string, vars Vars) error {
	data, err := yaml.Marshal(vars)
	if err != nil {
		return fmt.Errorf("marshal Goss vars: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write Goss vars: %w", err)
	}
	return nil
}
