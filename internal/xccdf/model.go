package xccdf

type Benchmark struct {
	ID          string
	Title       string
	Version     string
	ReleaseInfo string
	Rules       []Rule
}

type Rule struct {
	VulnID                  string
	RuleID                  string
	RuleIDSrc               string
	RuleVersion             string
	Title                   string
	GroupTitle              string
	GroupTreeTitle          string
	Severity                string
	Weight                  string
	Description             string
	Discussion              string
	FalsePositives          string
	FalseNegatives          string
	Documentable            string
	Mitigations             string
	SecurityOverrideGuidance string
	PotentialImpacts        string
	ThirdPartyTools         string
	MitigationControl       string
	Responsibility          string
	IAControls              string
	CheckContent            string
	FixText                 string
	CCIs                    []string
	LegacyIDs               []string
	ReferenceID             string
	CheckRefHref            string
	CheckRefName            string
}
