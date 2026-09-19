package rules

type Status string

const (
	StatusAutomated     Status = "automated"
	StatusManual        Status = "manual"
	StatusNotApplicable Status = "not_applicable"
	StatusTailored      Status = "tailored"
)

type Rule struct {
	VulnID   string `yaml:"-" json:"vuln_id"`
	Title    string `yaml:"title" json:"title"`
	RuleID   string `yaml:"rule_id" json:"rule_id"`
	Severity string `yaml:"severity" json:"severity"`
	Status   Status `yaml:"status" json:"status"`

	Remediation struct {
		File string `yaml:"file" json:"file"`
		Step string `yaml:"step" json:"step"`
	} `yaml:"remediation" json:"remediation"`

	Validation struct {
		Type     string `yaml:"type" json:"type"`
		File     string `yaml:"file" json:"file"`
		Resource string `yaml:"resource" json:"resource"`
		Test     string `yaml:"test" json:"test"`
	} `yaml:"validation" json:"validation"`
}

type Document struct {
	SchemaVersion int             `yaml:"schema_version"`
	Rules         map[string]Rule `yaml:"rules"`
}
