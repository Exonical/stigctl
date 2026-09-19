package exceptions

type Exception struct {
	VulnID string `yaml:"-" json:"vuln_id"`
	Status string `yaml:"status" json:"status"`

	Scope struct {
		All      bool     `yaml:"all" json:"all"`
		Profiles []string `yaml:"profiles" json:"profiles"`
		Hosts    []string `yaml:"hosts" json:"hosts"`
	} `yaml:"scope" json:"scope"`

	Justification struct {
		Reason string `yaml:"reason" json:"reason"`
		Impact string `yaml:"impact" json:"impact"`
		Risk   string `yaml:"risk" json:"risk"`
	} `yaml:"justification" json:"justification"`

	CompensatingControls []string `yaml:"compensating_controls" json:"compensating_controls"`

	Approval struct {
		Ticket       string `yaml:"ticket" json:"ticket"`
		Owner        string `yaml:"owner" json:"owner"`
		ApprovedBy   string `yaml:"approved_by" json:"approved_by"`
		ApprovedDate string `yaml:"approved_date" json:"approved_date"`
	} `yaml:"approval" json:"approval"`

	Lifecycle struct {
		Created            string `yaml:"created" json:"created"`
		Expires            string `yaml:"expires" json:"expires"`
		ReviewIntervalDays int    `yaml:"review_interval_days" json:"review_interval_days"`
	} `yaml:"lifecycle" json:"lifecycle"`
}

type Document struct {
	SchemaVersion int                  `yaml:"schema_version"`
	Exceptions    map[string]Exception `yaml:"exceptions"`
}
