package exceptions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/stigctl/internal/rules"
)

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Document)
		wantErr string
	}{
		{
			name: "invalid V-ID",
			mutate: func(doc *Document) {
				doc.Exceptions["bad-id"] = doc.Exceptions["V-1"]
				delete(doc.Exceptions, "V-1")
			},
			wantErr: "bad-id: invalid V-ID",
		},
		{
			name: "empty status",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Status = ""
				doc.Exceptions["V-1"] = exception
			},
			wantErr: "V-1: status must be exception or not_applicable",
		},
		{
			name: "hyphenated status",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Status = "not-applicable"
				doc.Exceptions["V-1"] = exception
			},
			wantErr: "V-1: status must be exception or not_applicable",
		},
		{
			name: "abbreviated status",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Status = "n/a"
				doc.Exceptions["V-1"] = exception
			},
			wantErr: "V-1: status must be exception or not_applicable",
		},
		{
			name: "missing reason",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Justification.Reason = " "
				doc.Exceptions["V-1"] = exception
			},
			wantErr: "V-1: justification.reason is required",
		},
		{
			name: "empty scope",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Scope.All = false
				doc.Exceptions["V-1"] = exception
			},
			wantErr: "V-1: scope must set all, profiles, or hosts",
		},
		{
			name: "invalid created date",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Lifecycle.Created = "2026/01/01"
				doc.Exceptions["V-1"] = exception
			},
			wantErr: "V-1: lifecycle.created must use YYYY-MM-DD",
		},
		{
			name: "invalid expires date",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Lifecycle.Expires = "2026-02-30"
				doc.Exceptions["V-1"] = exception
			},
			wantErr: "V-1: lifecycle.expires must use YYYY-MM-DD",
		},
		{
			name: "invalid approval date",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Approval.ApprovedDate = "January 1"
				doc.Exceptions["V-1"] = exception
			},
			wantErr: "V-1: approval.approved_date must use YYYY-MM-DD",
		},
		{
			name: "expires before created",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Lifecycle.Expires = "2025-12-31"
				doc.Exceptions["V-1"] = exception
			},
			wantErr: "V-1: lifecycle.expires must not be before lifecycle.created",
		},
		{
			name: "negative review interval",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Lifecycle.ReviewIntervalDays = -1
				doc.Exceptions["V-1"] = exception
			},
			wantErr: "V-1: lifecycle.review_interval_days must be at least 0",
		},
	}

	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := validDocument()
			tt.mutate(&doc)
			_, err := Validate(doc, now)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want text %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateWarnings(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*Document)
		now         time.Time
		wantWarning string
	}{
		{
			name: "approver missing",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Approval.ApprovedBy = ""
				doc.Exceptions["V-1"] = exception
			},
			now:         time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
			wantWarning: "V-1: approval.approved_by is not set",
		},
		{
			name: "expired",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Lifecycle.Expires = "2026-01-14"
				doc.Exceptions["V-1"] = exception
			},
			now:         time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
			wantWarning: "V-1: exception expired on 2026-01-14; the rule will be evaluated normally",
		},
		{
			name: "review overdue",
			mutate: func(doc *Document) {
				exception := doc.Exceptions["V-1"]
				exception.Lifecycle.ReviewIntervalDays = 10
				doc.Exceptions["V-1"] = exception
			},
			now:         time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
			wantWarning: "V-1: review overdue since 2026-01-11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := validDocument()
			tt.mutate(&doc)
			warnings, err := Validate(doc, tt.now)
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if !contains(warnings, tt.wantWarning) {
				t.Fatalf("Validate() warnings = %q, want %q", warnings, tt.wantWarning)
			}
		})
	}
}

func TestValidateValidDocument(t *testing.T) {
	warnings, err := Validate(validDocument(), time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Validate() warnings = %q, want none", warnings)
	}
}

func TestLoadRejectsInvalidStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exceptions.yaml")
	data := []byte("schema_version: 1\nexceptions:\n  V-1:\n    status: n/a\n    scope:\n      all: true\n    justification:\n      reason: test\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "V-1: status") {
		t.Fatalf("Load() error = %v, want invalid status", err)
	}
}

func TestCheckRuleReferences(t *testing.T) {
	doc := validDocument()
	doc.Exceptions["V-3"] = doc.Exceptions["V-1"]
	ruleDoc := rules.Document{Rules: map[string]rules.Rule{"V-1": {}}}

	err := CheckRuleReferences(doc, ruleDoc)
	if err == nil || !strings.Contains(err.Error(), "V-3") {
		t.Fatalf("CheckRuleReferences() error = %v, want V-3", err)
	}
}

func validDocument() Document {
	var exception Exception
	exception.Status = "exception"
	exception.Scope.All = true
	exception.Justification.Reason = "approved operational requirement"
	exception.Approval.ApprovedBy = "ISSO"
	exception.Approval.ApprovedDate = "2026-01-01"
	exception.Lifecycle.Created = "2026-01-01"
	exception.Lifecycle.Expires = "2026-12-31"
	return Document{Exceptions: map[string]Exception{"V-1": exception}}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
