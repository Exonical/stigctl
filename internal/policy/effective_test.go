package policy

import (
	"testing"
	"time"

	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/rules"
)

func TestEnabledRulesDisablesExceptionsAndManualRules(t *testing.T) {
	auto := rules.Rule{Status: rules.StatusAutomated}
	manual := rules.Rule{Status: rules.StatusManual}
	doc := rules.Document{Rules: map[string]rules.Rule{
		"V-1": auto,
		"V-2": manual,
	}}

	var exception exceptions.Exception
	exception.Status = "exception"
	exception.Scope.All = true
	exception.Justification.Reason = "Approved exception"
	exception.Lifecycle.Expires = "2027-01-01"
	exceptionDoc := exceptions.Document{Exceptions: map[string]exceptions.Exception{
		"V-1": exception,
	}}

	got := EnabledRules(doc, exceptionDoc, Context{
		Profile: "server",
		Now:     time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
	})

	if got["V-1"] {
		t.Fatal("excepted rule should be disabled")
	}
	if got["V-2"] {
		t.Fatal("manual rule should be disabled")
	}
}
