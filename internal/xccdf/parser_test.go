package xccdf

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	input := `<?xml version="1.0"?>
<Benchmark id="RHEL_9_STIG">
  <title>Red Hat Enterprise Linux 9 STIG</title>
  <version>2</version>
  <plain-text id="release-info">Release: 9 Benchmark Date: 01 Jan 2026</plain-text>
  <Group id="V-123456">
    <title>SRG-OS-000001</title>
    <Rule id="SV-123456r1_rule" severity="high" weight="10.0">
      <version>RHEL-09-000001</version>
      <title>Example requirement</title>
      <description>&lt;VulnDiscussion&gt;Example discussion&lt;/VulnDiscussion&gt;</description>
      <ident system="http://cyber.mil/cci">CCI-000001</ident>
      <fix>Apply the fix.</fix>
      <check>
        <check-content-ref href="RHEL_9_STIG.xml" name="M"/>
        <check-content>Run the check.</check-content>
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
	if len(got.Rules) != 1 {
		t.Fatalf("len(Rules) = %d", len(got.Rules))
	}
	rule := got.Rules[0]
	if rule.VulnID != "V-123456" {
		t.Fatalf("VulnID = %q", rule.VulnID)
	}
	if rule.RuleID != "SV-123456r1" {
		t.Fatalf("RuleID = %q", rule.RuleID)
	}
	if len(rule.CCIs) != 1 || rule.CCIs[0] != "CCI-000001" {
		t.Fatalf("CCIs = %#v", rule.CCIs)
	}
}
