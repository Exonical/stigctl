package xccdf

import (
	"strings"
	"testing"
)

func TestParseDISAXCCDF11(t *testing.T) {
	input := `<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG">
  <title>Red Hat Enterprise Linux 9 Security Technical Implementation Guide</title>
  <version>2</version>
  <plain-text id="release-info">Release: 9 Benchmark Date: 01 Jul 2026</plain-text>
  <Group id="V-257777">
    <title>SRG-OS-000480-GPOS-00227</title>
    <Rule id="SV-257777r1155676_rule" severity="high" weight="10.0">
      <version>RHEL-09-211010</version>
      <title>RHEL 9 must be a vendor-supported release.</title>
      <description>&lt;VulnDiscussion&gt;Example discussion&lt;/VulnDiscussion&gt;&lt;Documentable&gt;false&lt;/Documentable&gt;</description>
      <reference>
        <identifier>5551</identifier>
      </reference>
      <ident system="http://cyber.mil/cci">CCI-000366</ident>
      <fixtext fixref="F-61442r925317_fix">Upgrade to a supported version of RHEL 9.</fixtext>
      <fix id="F-61442r925317_fix"></fix>
      <check system="C-61518r1155675_chk">
        Verify the version of RHEL 9 is vendor supported.
      </check>
    </Rule>
  </Group>
</Benchmark>`

	got, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.ID != "RHEL_9_STIG" {
		t.Fatalf("ID = %q", got.ID)
	}
	if got.Version != "2" {
		t.Fatalf("Version = %q", got.Version)
	}
	if got.ReleaseInfo != "Release: 9 Benchmark Date: 01 Jul 2026" {
		t.Fatalf("ReleaseInfo = %q", got.ReleaseInfo)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("len(Rules) = %d", len(got.Rules))
	}

	rule := got.Rules[0]
	if rule.VulnID != "V-257777" {
		t.Fatalf("VulnID = %q", rule.VulnID)
	}
	if rule.RuleID != "SV-257777r1155676" {
		t.Fatalf("RuleID = %q", rule.RuleID)
	}
	if rule.RuleIDSrc != "SV-257777r1155676_rule" {
		t.Fatalf("RuleIDSrc = %q", rule.RuleIDSrc)
	}
	if rule.RuleVersion != "RHEL-09-211010" {
		t.Fatalf("RuleVersion = %q", rule.RuleVersion)
	}
	if rule.GroupTreeTitle != "SRG-OS-000480-GPOS-00227" {
		t.Fatalf("GroupTreeTitle = %q", rule.GroupTreeTitle)
	}
	if rule.FixText != "Upgrade to a supported version of RHEL 9." {
		t.Fatalf("FixText = %q", rule.FixText)
	}
	if rule.CheckContent != "Verify the version of RHEL 9 is vendor supported." {
		t.Fatalf("CheckContent = %q", rule.CheckContent)
	}
	if rule.CheckRefName != "C-61518r1155675_chk" {
		t.Fatalf("CheckRefName = %q", rule.CheckRefName)
	}
	if rule.ReferenceID != "5551" {
		t.Fatalf("ReferenceID = %q", rule.ReferenceID)
	}
	if len(rule.CCIs) != 1 || rule.CCIs[0] != "CCI-000366" {
		t.Fatalf("CCIs = %#v", rule.CCIs)
	}
}
