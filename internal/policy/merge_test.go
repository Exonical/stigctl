package policy

import (
	"testing"
	"time"

	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/results"
	"github.com/Exonical/stigctl/internal/rules"
)

func TestMergeExceptionOverridesTechnicalResult(t *testing.T) {
	var rule rules.Rule
	rule.VulnID = "V-1"
	rule.Title = "Example"
	rule.Status = rules.StatusAutomated

	ruleDoc := rules.Document{Rules: map[string]rules.Rule{"V-1": rule}}

	var exception exceptions.Exception
	exception.VulnID = "V-1"
	exception.Status = "exception"
	exception.Scope.Profiles = []string{"hpc-compute"}
	exception.Justification.Reason = "Required for workload"

	exceptionDoc := exceptions.Document{Exceptions: map[string]exceptions.Exception{"V-1": exception}}

	got := Merge(
		ruleDoc,
		exceptionDoc,
		[]results.Result{{VulnID: "V-1", Status: results.StatusFail}},
		Context{
			Profile: "hpc-compute",
			Now:     time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
		},
	)

	if len(got) != 1 {
		t.Fatalf("len(results) = %d", len(got))
	}
	if got[0].Status != results.StatusException {
		t.Fatalf("Status = %q", got[0].Status)
	}
}

func TestMergeNotApplicablePolicyOverlay(t *testing.T) {
	var rule rules.Rule
	rule.VulnID = "V-2"
	rule.Title = "Conditional requirement"
	rule.Status = rules.StatusAutomated

	ruleDoc := rules.Document{Rules: map[string]rules.Rule{"V-2": rule}}

	var exception exceptions.Exception
	exception.VulnID = "V-2"
	exception.Status = "not_applicable"
	exception.Scope.Profiles = []string{"server"}
	exception.Justification.Reason = "Alternate control applies."

	exceptionDoc := exceptions.Document{Exceptions: map[string]exceptions.Exception{"V-2": exception}}

	got := Merge(
		ruleDoc,
		exceptionDoc,
		[]results.Result{{VulnID: "V-2", Status: results.StatusFail}},
		Context{
			Profile: "server",
			Now:     time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
		},
	)

	if len(got) != 1 {
		t.Fatalf("len(results) = %d", len(got))
	}
	if got[0].Status != results.StatusNotApplicable {
		t.Fatalf("Status = %q", got[0].Status)
	}
}
