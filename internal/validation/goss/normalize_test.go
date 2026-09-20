package goss

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Exonical/stigctl/internal/results"
	"github.com/goss-org/goss/resource"
)

func TestNormalizeResults(t *testing.T) {
	validationErr := resource.ValidateError("resource unavailable")
	tests := []struct {
		name         string
		tests        []resource.TestResult
		wantStatus   results.Status
		wantEvidence string
	}{
		{
			name: "validation error",
			tests: []resource.TestResult{{
				ResourceId: "V-1", Result: resource.FAIL, Err: &validationErr,
			}},
			wantStatus:   results.StatusError,
			wantEvidence: "resource unavailable",
		},
		{
			name: "genuine failure wins over error",
			tests: []resource.TestResult{
				{ResourceId: "V-1", Result: resource.FAIL},
				{ResourceId: "V-1", Result: resource.FAIL, Err: &validationErr},
			},
			wantStatus: results.StatusFail,
		},
		{
			name:       "all successful",
			tests:      []resource.TestResult{{ResourceId: "V-1", Result: resource.SUCCESS}},
			wantStatus: results.StatusPass,
		},
		{
			name:       "all skipped",
			tests:      []resource.TestResult{{ResourceId: "V-1", Result: resource.SKIP, Skipped: true}},
			wantStatus: results.StatusSkipped,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeResults(tt.tests)
			if len(got) != 1 {
				t.Fatalf("normalizeResults() returned %d results, want 1", len(got))
			}
			if got[0].Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", got[0].Status, tt.wantStatus)
			}
			if tt.wantEvidence != "" {
				if len(got[0].Evidence) == 0 || !strings.Contains(got[0].Evidence[0].Message, tt.wantEvidence) {
					t.Errorf("evidence = %#v, want text %q", got[0].Evidence, tt.wantEvidence)
				}
			}
		})
	}
}

func TestFormatMatcherValue(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		got := formatMatcherValue("evidence=ok\n")
		if got != "evidence=ok" {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, "evidence=ok")
		}
	})

	t.Run("bytes", func(t *testing.T) {
		got := formatMatcherValue([]byte("evidence=ok\n"))
		if got != "evidence=ok" {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, "evidence=ok")
		}
	})

	t.Run("advanced reader", func(t *testing.T) {
		reader := bytes.NewReader([]byte("evidence=permissive=missing last_rule=deny perm=any all : all\n"))
		if _, err := reader.Seek(0, 2); err != nil {
			t.Fatal(err)
		}

		got := formatMatcherValue(reader)
		want := "evidence=permissive=missing last_rule=deny perm=any all : all"
		if got != want {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, want)
		}
	})

	t.Run("ordinary scalar", func(t *testing.T) {
		got := formatMatcherValue(1)
		if got != "1" {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, "1")
		}
	})

	t.Run("buffer", func(t *testing.T) {
		got := formatMatcherValue(bytes.NewBufferString("line one\n"))
		if got != "line one" {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, "line one")
		}
	})

	t.Run("multiline preserves content", func(t *testing.T) {
		got := formatMatcherValue(strings.NewReader("line one\nline two\n"))
		want := "line one\nline two"
		if got != want {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, want)
		}
	})
}
