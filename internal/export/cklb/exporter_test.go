package cklb

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Exonical/stigctl/internal/exceptions"
	stigexport "github.com/Exonical/stigctl/internal/export"
	"github.com/Exonical/stigctl/internal/policy"
	"github.com/Exonical/stigctl/internal/results"
	"github.com/Exonical/stigctl/internal/rules"
	"github.com/Exonical/stigctl/internal/xccdf"
)

func TestExportMapsStatuses(t *testing.T) {
	ids := []string{
		"V-pass", "V-fail", "V-skipped", "V-error", "V-manual",
		"V-rule-na", "V-exception", "V-exception-na", "V-missing",
	}
	benchmark := xccdf.Benchmark{
		ID:          "RHEL_9_STIG",
		Title:       "Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
		Version:     "2",
		ReleaseInfo: "Release: 9",
		Rules:       make([]xccdf.Rule, 0, len(ids)),
	}
	ruleDoc := rules.Document{Rules: map[string]rules.Rule{}}
	for _, id := range ids {
		benchmark.Rules = append(benchmark.Rules, xccdf.Rule{
			VulnID:         id,
			RuleID:         "SV-" + id,
			RuleIDSrc:      "SV-" + id + "_rule",
			RuleVersion:    "RHEL-09-000001",
			Title:          "Example rule " + id,
			GroupTitle:     "Example rule " + id,
			GroupTreeTitle: "SRG-OS-000480-GPOS-00227",
			Severity:       "high",
			Weight:         "10.0",
			CheckContent:   "Check it.",
			FixText:        "Fix it.",
		})
		status := rules.StatusAutomated
		switch id {
		case "V-manual":
			status = rules.StatusManual
		case "V-rule-na":
			status = rules.StatusNotApplicable
		}
		ruleDoc.Rules[id] = rules.Rule{VulnID: id, Title: "Example rule " + id, Status: status}
	}

	exceptionDoc := exceptions.Document{Exceptions: map[string]exceptions.Exception{}}
	var exception exceptions.Exception
	exception.Status = "exception"
	exception.Scope.All = true
	exception.Justification.Reason = "Approved exception"
	exception.Approval.Ticket = "RMF-1"
	exceptionDoc.Exceptions["V-exception"] = exception
	notApplicable := exception
	notApplicable.Status = "not_applicable"
	exceptionDoc.Exceptions["V-exception-na"] = notApplicable

	merged := policy.Merge(ruleDoc, exceptionDoc, []results.Result{
		{VulnID: "V-pass", Status: results.StatusPass},
		{VulnID: "V-fail", Status: results.StatusFail},
		{VulnID: "V-skipped", Status: results.StatusSkipped},
		{VulnID: "V-error", Status: results.StatusError},
		{VulnID: "V-exception", Status: results.StatusFail},
		{VulnID: "V-exception-na", Status: results.StatusFail},
	}, policy.Context{Profile: "server", Now: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)})

	var buf bytes.Buffer
	err := (Exporter{}).Export(context.Background(), &buf, stigexport.Request{
		Baseline:  "rhel9:v2r9",
		Benchmark: benchmark,
		Target:    stigexport.Target{Hostname: "node01"},
		Results:   merged,
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
	if got.STIGs[0].DisplayName != "Red Hat Enterprise Linux 9" {
		t.Fatalf("display_name = %q", got.STIGs[0].DisplayName)
	}
	if !got.Active {
		t.Fatal("expected active checklist")
	}
	if got.TargetData.TechnologyArea != "" {
		t.Fatalf("technology_area = %q, want empty", got.TargetData.TechnologyArea)
	}
	if len(got.STIGs) != 1 || len(got.STIGs[0].Rules) != len(ids) {
		t.Fatalf("unexpected STIG/rule count")
	}

	wantStatuses := map[string]string{
		"V-pass":         "not_a_finding",
		"V-fail":         "open",
		"V-skipped":      "not_reviewed",
		"V-error":        "not_reviewed",
		"V-manual":       "not_reviewed",
		"V-rule-na":      "not_applicable",
		"V-exception":    "open",
		"V-exception-na": "not_applicable",
		"V-missing":      "not_reviewed",
	}
	for _, rule := range got.STIGs[0].Rules {
		if want := wantStatuses[rule.GroupID]; rule.Status != want {
			t.Errorf("%s status = %q, want %q", rule.GroupID, rule.Status, want)
		}
		if rule.GroupID == "V-exception" && rule.Comments == "" {
			t.Error("exception comments were not exported")
		}
		if rule.SRGID != "SRG-OS-000480-GPOS-00227" {
			t.Errorf("%s srg_id = %q", rule.GroupID, rule.SRGID)
		}
		if len(rule.GroupTree) != 1 || rule.GroupTree[0].Description != "<GroupDescription></GroupDescription>" {
			t.Errorf("%s unexpected group_tree = %#v", rule.GroupID, rule.GroupTree)
		}
	}
}
