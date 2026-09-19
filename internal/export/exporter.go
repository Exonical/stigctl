package export

import (
	"context"
	"io"

	"github.com/Exonical/stigctl/internal/results"
	"github.com/Exonical/stigctl/internal/xccdf"
)

type Target struct {
	Hostname   string
	IPAddress  string
	MACAddress string
	FQDN       string
	Comments   string
	Role       string
}

type Request struct {
	Baseline  string
	Benchmark xccdf.Benchmark
	Target    Target
	Results   []results.Result
}

type Exporter interface {
	Export(context.Context, io.Writer, Request) error
}
