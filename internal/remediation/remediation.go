package remediation

import "context"

type Request struct {
	Baseline string
	Profile  string
	Rules    []string
}

type Result struct {
	Applied []string
	Skipped []string
	Failed  []string
}

type Remediator interface {
	Apply(context.Context, Request) (Result, error)
}
