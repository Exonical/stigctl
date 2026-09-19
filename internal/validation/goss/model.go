package goss

type Output struct {
	Results []TestResult `json:"results"`
	Summary Summary      `json:"summary"`
}

type Summary struct {
	TestCount    int    `json:"test-count"`
	FailedCount  int    `json:"failed-count"`
	SkippedCount int    `json:"skipped-count"`
	SummaryLine  string `json:"summary-line"`
}

type TestResult struct {
	Successful   bool           `json:"successful"`
	Skipped      bool           `json:"skipped"`
	ResourceID   string         `json:"resource-id"`
	ResourceType string         `json:"resource-type"`
	Property     string         `json:"property"`
	Title        string         `json:"title"`
	Meta         map[string]any `json:"meta"`
	Result       int            `json:"result"`
	Err          any            `json:"err"`
	Matcher      MatcherResult  `json:"matcher-result"`
	SummaryLine  string         `json:"summary-line"`
}

type MatcherResult struct {
	Actual   any    `json:"actual"`
	Expected any    `json:"expected"`
	Message  string `json:"message"`
}
