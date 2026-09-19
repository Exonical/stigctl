package remediation

import "context"

type Request struct {
	Baseline string
	Profile  string
	Stage    string
	Files    []string
}

type Result struct {
	Files  []string
	Stdout string
	Stderr string
}

type Remediator interface {
	Apply(context.Context, Request) (Result, error)
}
