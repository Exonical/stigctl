package cklb

import (
	"testing"

	"github.com/Exonical/stigctl/internal/xccdf"
)

func TestCompareBenchmarkNormalizesLineEndingsAndTrailingWhitespace(t *testing.T) {
	benchmark := xccdf.Benchmark{
		ID:          "RHEL_9_STIG",
		Title:       "Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
		Version:     "2",
		ReleaseInfo: "Release: 9 Benchmark Date: 01 Jul 2026",
		Rules: []xccdf.Rule{{
			VulnID:        "V-1",
			RuleID:        "SV-1r1",
			RuleIDSrc:     "SV-1r1_rule",
			RuleVersion:   "RHEL-09-000001",
			Title:         "Example",
			GroupTitle:    "Example",
			GroupTreeTitle:"SRG-OS-000001",
			Severity:      "high",
			Weight:        "10.0",
			FixText:       "line one\nline two",
			CheckContent:  "check one\ncheck two",
			CheckRefHref:  "RHEL.xml",
			CheckRefName:  "M",
			CCIs:          []string{"CCI-000001"},
		}},
	}

	doc := Document{
		STIGs: []STIG{{
			STIGName:    benchmark.Title,
			STIGID:      benchmark.ID,
			Version:     benchmark.Version,
			ReleaseInfo: benchmark.ReleaseInfo,
			Rules: []Rule{{
				GroupIDSrc:    "V-1",
				GroupID:       "V-1",
				RuleIDSrc:     "SV-1r1_rule",
				RuleID:        "SV-1r1",
				RuleVersion:   "RHEL-09-000001",
				RuleTitle:     "Example",
				GroupTitle:    "Example",
				Severity:      "high",
				Weight:        "10.0",
				FixText:       "line one\r\nline two ",
				CheckContent:  "check one\r\ncheck two",
				CheckContentRef: CheckContentRef{Href: "RHEL.xml", Name: "M"},
				CCIs:          []string{"CCI-000001"},
				SRGID:         "SRG-OS-000001",
				GroupTree:     []GroupTree{{ID: "V-1", Title: "SRG-OS-000001"}},
			}},
		}},
	}

	if got := CompareBenchmark(doc, benchmark); len(got) != 0 {
		t.Fatalf("mismatches = %#v", got)
	}
}
