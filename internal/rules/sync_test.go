package rules

import (
	"testing"

	"github.com/Exonical/stigctl/internal/xccdf"
)

func TestSyncPreservesImplementationMetadata(t *testing.T) {
	var existing Rule
	existing.Status = StatusAutomated
	existing.Validation.Type = "goss"
	existing.Validation.File = "validation/30-ssh.yaml"
	existing.Validation.Test = "V-1"

	doc := Document{
		SchemaVersion: 1,
		Rules: map[string]Rule{
			"V-1": existing,
		},
	}

	benchmark := xccdf.Benchmark{
		Rules: []xccdf.Rule{
			{
				VulnID:   "V-1",
				RuleID:   "SV-1r1",
				Title:    "Updated title",
				Severity: "high",
			},
			{
				VulnID:   "V-2",
				RuleID:   "SV-2r1",
				Title:    "New rule",
				Severity: "medium",
			},
		},
	}

	got := Sync(doc, benchmark)
	if got.Rules["V-1"].Status != StatusAutomated {
		t.Fatalf("existing status was not preserved")
	}
	if got.Rules["V-1"].Validation.Type != "goss" {
		t.Fatalf("existing validation mapping was not preserved")
	}
	if got.Rules["V-1"].Title != "Updated title" {
		t.Fatalf("title was not refreshed")
	}
	if got.Rules["V-2"].Status != StatusManual {
		t.Fatalf("new rules should default to manual, got %q", got.Rules["V-2"].Status)
	}
}
