package goss

import (
	"strings"
	"testing"

	"github.com/Exonical/stigctl/internal/results"
)

func TestParseGroupsResultsBySTIGID(t *testing.T) {
	input := `{
	  "results": [
	    {
	      "successful": true,
	      "skipped": false,
	      "resource-id": "root-login",
	      "resource-type": "Command",
	      "property": "exit-status",
	      "title": "V-123456 - root login",
	      "meta": {"stig_id": "V-123456"},
	      "result": 0,
	      "summary-line": "matches expectation"
	    },
	    {
	      "successful": false,
	      "skipped": false,
	      "resource-id": "root-login",
	      "resource-type": "Command",
	      "property": "stdout",
	      "title": "V-123456 - root login",
	      "meta": {"stig_id": "V-123456"},
	      "result": 1,
	      "summary-line": "does not match expectation"
	    }
	  ],
	  "summary": {
	    "test-count": 2,
	    "failed-count": 1,
	    "skipped-count": 0,
	    "summary-line": "Count: 2, Failed: 1, Skipped: 0"
	  }
	}`

	got, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(got))
	}
	if got[0].VulnID != "V-123456" {
		t.Fatalf("VulnID = %q", got[0].VulnID)
	}
	if got[0].Status != results.StatusFail {
		t.Fatalf("Status = %q, want %q", got[0].Status, results.StatusFail)
	}
}

func TestParseSkippedRule(t *testing.T) {
	input := `{
	  "results": [{
	    "successful": true,
	    "skipped": true,
	    "resource-id": "V-123457",
	    "resource-type": "File",
	    "property": "exists",
	    "title": "V-123457",
	    "meta": {},
	    "result": 2,
	    "summary-line": "skipped"
	  }],
	  "summary": {"test-count": 1, "failed-count": 0, "skipped-count": 1}
	}`

	got, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got[0].Status != results.StatusSkipped {
		t.Fatalf("Status = %q, want %q", got[0].Status, results.StatusSkipped)
	}
}
