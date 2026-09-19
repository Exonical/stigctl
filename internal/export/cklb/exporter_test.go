package cklb

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	stigexport "github.com/Exonical/stigctl/internal/export"
	"github.com/Exonical/stigctl/internal/results"
	"github.com/Exonical/stigctl/internal/xccdf"
)

func TestExportMapsStatuses(t *testing.T) {
	benchmark := xccdf.Benchmark{
		ID:          "RHEL_9_STIG",
		Title:       "Red Hat Enterprise Linux 9 STIG",
		Version:     "2",
		ReleaseInfo: "Release: 9",
		Rules: []xccdf.Rule{
			{
				VulnID:       "V-1",
				RuleID:       "SV-1r1",
				RuleIDSrc:    "SV-1r1_rule",
				RuleVersion:  "RHEL-09-000001",
				Title:        "Example rule",
				GroupTitle:   "Example rule",
				Severity:     "high",
				Weight:       "10.0",
				CheckContent: "Check it.",
				FixText:      "Fix it.",
			},
		},
	}

	var buf bytes.Buffer
	err := (Exporter{}).Export(context.Background(), &buf, stigexport.Request{
		Baseline:  "rhel9:v2r9",
		Benchmark: benchmark,
		Target:    stigexport.Target{Hostname: "node01"},
		Results: []results.Result{
			{
				VulnID:         "V-1",
				Status:         results.StatusException,
				Comments:       "Approved exception; ticket=RMF-1",
				FindingDetails: "Technical control is excepted.",
			},
		},
	})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	var got Document
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode CKLB: %v", err)
	}
	if got.CKLBVersion != "1.0" {
		t.Fatalf("cklb_version = %q", got.CKLBVersion)
	}
	if len(got.STIGs) != 1 || len(got.STIGs[0].Rules) != 1 {
		t.Fatalf("unexpected STIG/rule count")
	}
	rule := got.STIGs[0].Rules[0]
	if rule.Status != "open" {
		t.Fatalf("exception status = %q, want open", rule.Status)
	}
	if rule.Comments == "" {
		t.Fatal("exception comments were not exported")
	}
}
