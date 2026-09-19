package export

import (
	"context"
	"io"

	"github.com/Exonical/stigctl/internal/results"
)

type Request struct {
	Baseline string
	Hostname string
	Results  []results.Result
}

type Exporter interface {
	Export(context.Context, io.Writer, Request) error
}
