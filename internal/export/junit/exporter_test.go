package junit

import (
	"bytes"
	"context"
	"encoding/xml"
	"strings"
	"testing"

	stigexport "github.com/Exonical/stigctl/internal/export"
	"github.com/Exonical/stigctl/internal/results"
)

func TestExportMapsSTIGStatusesToJUnit(t *testing.T) {
	req := stigexport.Request{
		Baseline: "rhel9:v2r9",
		Target:   stigexport.Target{Hostname: "node01"},
		Results: []results.Result{
			{VulnID: "V-1", RuleID: "SV-1", Title: "Passing rule", Severity: "low", Status: results.StatusPass},
			{VulnID: "V-2", RuleID: "SV-2", Title: "Failing <rule>", Severity: "high", Status: results.StatusFail, FindingDetails: "expected=0 & actual=1"},
			{VulnID: "V-3", RuleID: "SV-3", Title: "Validation error", Severity: "medium", Status: results.StatusError, FindingDetails: "command failed"},
			{VulnID: "V-4", RuleID: "SV-4", Title: "Manual rule", Severity: "medium", Status: results.StatusManual},
			{VulnID: "V-5", RuleID: "SV-5", Title: "Exception", Severity: "medium", Status: results.StatusException},
		},
	}
	var output bytes.Buffer
	if err := (Exporter{}).Export(context.Background(), &output, req); err != nil {
		t.Fatal(err)
	}
	var suite testSuite
	if err := xml.Unmarshal(output.Bytes(), &suite); err != nil {
		t.Fatalf("invalid JUnit XML: %v\n%s", err, output.String())
	}
	if suite.Tests != 5 || suite.Failures != 1 || suite.Errors != 1 || suite.Skipped != 2 {
		t.Fatalf("unexpected counters: %#v", suite)
	}
	if suite.Hostname != "node01" {
		t.Fatalf("hostname = %q", suite.Hostname)
	}
	if suite.Cases[1].Failure == nil || suite.Cases[1].Failure.Type != "stig_finding" {
		t.Fatalf("failure not mapped: %#v", suite.Cases[1])
	}
	if !strings.Contains(output.String(), "Failing &lt;rule&gt;") || !strings.Contains(output.String(), "expected=0 &amp; actual=1") {
		t.Fatalf("XML values were not escaped:\n%s", output.String())
	}
}

func TestExportHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (Exporter{}).Export(ctx, &bytes.Buffer{}, stigexport.Request{}); err == nil {
		t.Fatal("expected cancellation error")
	}
}
