package results

type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusNotApplicable Status = "not_applicable"
	StatusException     Status = "exception"
	StatusManual        Status = "manual"
	StatusError         Status = "error"
)

type Evidence struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type Result struct {
	VulnID         string     `json:"vuln_id"`
	RuleID         string     `json:"rule_id"`
	Title          string     `json:"title"`
	Severity       string     `json:"severity"`
	Status         Status     `json:"status"`
	FindingDetails string     `json:"finding_details,omitempty"`
	Comments       string     `json:"comments,omitempty"`
	Evidence       []Evidence `json:"evidence,omitempty"`
}
