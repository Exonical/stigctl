package profile

type Document struct {
	SchemaVersion int `yaml:"schema_version" json:"schema_version"`
	Profile       struct {
		ID          string `yaml:"id" json:"id"`
		Name        string `yaml:"name" json:"name"`
		Description string `yaml:"description,omitempty" json:"description,omitempty"`
	} `yaml:"profile" json:"profile"`
}
