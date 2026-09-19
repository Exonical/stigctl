package baseline

type Manifest struct {
	SchemaVersion int `yaml:"schema_version" json:"schema_version"`

	Profile struct {
		ID   string `yaml:"id" json:"id"`
		Name string `yaml:"name" json:"name"`
	} `yaml:"profile" json:"profile"`

	OS struct {
		Family       string `yaml:"family" json:"family"`
		MajorVersion int    `yaml:"major_version" json:"major_version"`
	} `yaml:"os" json:"os"`

	Baseline struct {
		Authority   string `yaml:"authority" json:"authority"`
		Version     int    `yaml:"version" json:"version"`
		Release     int    `yaml:"release" json:"release"`
		Identifier  string `yaml:"identifier" json:"identifier"`
		DisplayName string `yaml:"display_name" json:"display_name"`
	} `yaml:"baseline" json:"baseline"`

	Implementation struct {
		Revision int `yaml:"revision" json:"revision"`
	} `yaml:"implementation" json:"implementation"`

	Status string `yaml:"status" json:"status"`
}
