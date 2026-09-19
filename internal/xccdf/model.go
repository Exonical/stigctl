package xccdf

type Benchmark struct {
	ID          string
	Title       string
	Version     string
	ReleaseInfo string
	Rules       []Rule
}

type Rule struct {
	VulnID       string
	RuleID       string
	RuleVersion  string
	Title        string
	GroupTitle   string
	Severity     string
	Weight       string
	Description  string
	Discussion   string
	CheckContent string
	FixText      string
	CCIs         []string
	LegacyIDs    []string
	ReferenceID  string
	CheckRefHref string
	CheckRefName string
}
