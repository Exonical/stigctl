package validation

import (
	"context"

	"github.com/Exonical/stigctl/internal/results"
)

type Request struct {
	Baseline string
	Profile  string
	GossFile string
	Vars     []string
	Package  string
}

type Validator interface {
	Validate(context.Context, Request) ([]results.Result, error)
}
