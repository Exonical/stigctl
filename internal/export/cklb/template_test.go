package cklb

import (
	"strings"
	"testing"

	stigexport "github.com/Exonical/stigctl/internal/export"
	"github.com/Exonical/stigctl/internal/results"
)

func TestOverlayPreservesTemplateMetadata(t *testing.T) {
	input := `{
	  "title":"RHEL_9_Dev",
	  "id":"3b17b9c0-9d85-432d-8c72-19a455d462bb",
	  "stigs":[{
	    "stig_name":"Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
	    "display_name":"Red Hat Enterprise Linux 9",
	    "stig_id":"RHEL_9_STIG",
	    "release_info":"Release: 9 Benchmark Date: 01 Jul 2026",
	    "version":"2",
	    "uuid":"d73ef127-0032-4da8-921b-eccf72c9367e",
	    "reference_identifier":"5551",
	    "size":1,
	    "rules":[{
	      "group_id_src":"V-257777",
	      "group_tree":[{"id":"V-257777","title":"SRG-OS-000480-GPOS-00227","description":"<GroupDescription></GroupDescription>"}],
	      "group_id":"V-257777",
	      "severity":"high",
	      "group_title":"RHEL 9 must be a vendor-supported release.",
	      "rule_id_src":"SV-257777r1155676_rule",
	      "rule_id":"SV-257777r1155676",
	      "rule_version":"RHEL-09-211010",
	      "rule_title":"RHEL 9 must be a vendor-supported release.",
	      "fix_text":"Upgrade to a supported version of RHEL 9.",
	      "weight":"10.0",
	      "check_content":"Verify the version.",
	      "check_content_ref":{"href":"Red_Hat_Enterprise_Linux_9_STIG.xml","name":"M"},
	      "classification":"Unclassified",
	      "discussion":"discussion",
	      "false_positives":"",
	      "false_negatives":"",
	      "documentable":"false",
	      "security_override_guidance":"",
	      "potential_impacts":"",
	      "third_party_tools":"",
	      "ia_controls":"",
	      "responsibility":"",
	      "mitigations":"",
	      "mitigation_control":"",
	      "legacy_ids":[],
	      "ccis":["CCI-000366"],
	      "reference_identifier":"5551",
	      "uuid":"ba12944c-f160-492d-a44e-6edda6b85a77",
	      "stig_uuid":"d73ef127-0032-4da8-921b-eccf72c9367e",
	      "status":"not_reviewed",
	      "overrides":{},
	      "comments":"",
	      "finding_details":"",
	      "srg_id":"SRG-OS-000480-GPOS-00227"
	    }]
	  }],
	  "active":true,
	  "mode":2,
	  "has_path":false,
	  "target_data":{"target_type":"Computing","host_name":"","ip_address":"","mac_address":"","fqdn":"","comments":"","role":"None","is_web_database":false,"technology_area":"","web_db_site":"","web_db_instance":"","classification":null},
	  "cklb_version":"1.0"
	}`

	doc, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	got, err := Overlay(doc, stigexport.Request{
		Baseline: "rhel9:v2r9",
		Target: stigexport.Target{
			Hostname:  "node01",
			IPAddress: "10.0.0.1",
		},
		Results: []results.Result{{
			VulnID:         "V-257777",
			Status:         results.StatusPass,
			FindingDetails: "Automated validation passed.",
		}},
	})
	if err != nil {
		t.Fatalf("Overlay() error = %v", err)
	}

	rule := got.STIGs[0].Rules[0]
	if rule.UUID != "ba12944c-f160-492d-a44e-6edda6b85a77" {
		t.Fatalf("rule UUID changed: %q", rule.UUID)
	}
	if got.STIGs[0].UUID != "d73ef127-0032-4da8-921b-eccf72c9367e" {
		t.Fatalf("STIG UUID changed: %q", got.STIGs[0].UUID)
	}
	if rule.Status != "not_a_finding" {
		t.Fatalf("status = %q", rule.Status)
	}
	if got.TargetData.HostName != "node01" {
		t.Fatalf("hostname = %q", got.TargetData.HostName)
	}
	if got.TargetData.IPAddress != "10.0.0.1" {
		t.Fatalf("ip = %q", got.TargetData.IPAddress)
	}
}

func TestSanitizeTemplateClearsTargetAndReviewData(t *testing.T) {
	doc := Document{
		Title: "host-specific",
		ID:    "old-id",
		TargetData: TargetData{
			HostName:       "secret-host",
			IPAddress:      "10.0.0.1",
			MACAddress:     "00:11:22:33:44:55",
			FQDN:           "secret.example",
			Comments:       "host note",
			Role:           "Member Server",
			Classification: func() *string { v := "CUI"; return &v }(),
		},
		STIGs: []STIG{{
			UUID: "stig-uuid",
			Rules: []Rule{{
				UUID:           "rule-uuid",
				STIGUUID:       "stig-uuid",
				Status:         "open",
				Comments:       "finding note",
				FindingDetails: "finding",
				Overrides:      map[string]any{"severity": map[string]any{"severity": "medium"}},
			}},
		}},
		CKLBVersion: "1.0",
	}

	got, err := SanitizeTemplate(doc, "rhel9:v2r9")
	if err != nil {
		t.Fatalf("SanitizeTemplate() error = %v", err)
	}
	if got.Title != "rhel9:v2r9" {
		t.Fatalf("title = %q", got.Title)
	}
	if got.TargetData.HostName != "" || got.TargetData.IPAddress != "" || got.TargetData.FQDN != "" {
		t.Fatalf("target data was not cleared: %#v", got.TargetData)
	}
	if got.TargetData.Role != "None" {
		t.Fatalf("role = %q", got.TargetData.Role)
	}
	rule := got.STIGs[0].Rules[0]
	if rule.Status != "not_reviewed" || rule.Comments != "" || rule.FindingDetails != "" {
		t.Fatalf("rule review data was not cleared: %#v", rule)
	}
	if rule.UUID != "rule-uuid" || got.STIGs[0].UUID != "stig-uuid" {
		t.Fatal("template STIG/rule UUIDs should be preserved")
	}
}
