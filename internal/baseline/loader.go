package baseline

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}

	var manifest Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.SchemaVersion == 0 {
		return Manifest{}, fmt.Errorf("manifest schema_version is required")
	}
	if manifest.Profile.ID == "" {
		return Manifest{}, fmt.Errorf("manifest profile.id is required")
	}
	if manifest.OS.Family == "" || manifest.OS.MajorVersion == 0 {
		return Manifest{}, fmt.Errorf("manifest os family and major_version are required")
	}
	if manifest.Baseline.Authority == "" || manifest.Baseline.Version == 0 || manifest.Baseline.Release == 0 {
		return Manifest{}, fmt.Errorf("manifest baseline authority, version, and release are required")
	}

	return manifest, nil
}
