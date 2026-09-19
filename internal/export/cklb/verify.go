package cklb

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Exonical/stigctl/internal/xccdf"
)

type Mismatch struct {
	VulnID string
	Field  string
	Want   string
	Got    string
}

func CompareBenchmark(doc Document, benchmark xccdf.Benchmark) []Mismatch {
	var mismatches []Mismatch
	if len(doc.STIGs) != 1 {
		return []Mismatch{{Field: "stigs", Want: "1", Got: fmt.Sprint(len(doc.STIGs))}}
	}

	stig := doc.STIGs[0]
	compare := func(vulnID, field, want, got string) {
		if normalizeText(want) != normalizeText(got) {
			mismatches = append(mismatches, Mismatch{
				VulnID: vulnID,
				Field:  field,
				Want:   want,
				Got:    got,
			})
		}
	}

	compare("", "stig_id", benchmark.ID, stig.STIGID)
	compare("", "stig_name", benchmark.Title, stig.STIGName)
	compare("", "version", benchmark.Version, stig.Version)
	compare("", "release_info", benchmark.ReleaseInfo, stig.ReleaseInfo)
	if len(benchmark.Rules) != len(stig.Rules) {
		mismatches = append(mismatches, Mismatch{
			Field: "rule_count",
			Want:  fmt.Sprint(len(benchmark.Rules)),
			Got:   fmt.Sprint(len(stig.Rules)),
		})
	}

	templateRules := make(map[string]Rule, len(stig.Rules))
	for _, rule := range stig.Rules {
		templateRules[rule.GroupID] = rule
	}

	for _, source := range benchmark.Rules {
		rule, ok := templateRules[source.VulnID]
		if !ok {
			mismatches = append(mismatches, Mismatch{
				VulnID: source.VulnID,
				Field:  "rule",
				Want:   "present",
				Got:    "missing",
			})
			continue
		}

		compare(source.VulnID, "group_id_src", source.VulnID, rule.GroupIDSrc)
		compare(source.VulnID, "group_id", source.VulnID, rule.GroupID)
		compare(source.VulnID, "rule_id_src", source.RuleIDSrc, rule.RuleIDSrc)
		compare(source.VulnID, "rule_id", source.RuleID, rule.RuleID)
		compare(source.VulnID, "rule_version", source.RuleVersion, rule.RuleVersion)
		compare(source.VulnID, "rule_title", source.Title, rule.RuleTitle)
		compare(source.VulnID, "group_title", source.GroupTitle, rule.GroupTitle)
		compare(source.VulnID, "severity", source.Severity, rule.Severity)
		compare(source.VulnID, "weight", source.Weight, rule.Weight)
		compare(source.VulnID, "fix_text", source.FixText, rule.FixText)
		compare(source.VulnID, "check_content", source.CheckContent, rule.CheckContent)
		compare(source.VulnID, "check_content_ref.href", source.CheckRefHref, rule.CheckContentRef.Href)
		compare(source.VulnID, "check_content_ref.name", source.CheckRefName, rule.CheckContentRef.Name)
		compare(source.VulnID, "discussion", source.Discussion, rule.Discussion)
		compare(source.VulnID, "documentable", source.Documentable, rule.Documentable)
		compare(source.VulnID, "security_override_guidance", source.SecurityOverrideGuidance, rule.SecurityOverrideGuidance)
		compare(source.VulnID, "potential_impacts", source.PotentialImpacts, rule.PotentialImpacts)
		compare(source.VulnID, "third_party_tools", source.ThirdPartyTools, rule.ThirdPartyTools)
		compare(source.VulnID, "ia_controls", source.IAControls, rule.IAControls)
		compare(source.VulnID, "responsibility", source.Responsibility, rule.Responsibility)
		compare(source.VulnID, "mitigations", source.Mitigations, rule.Mitigations)
		compare(source.VulnID, "mitigation_control", source.MitigationControl, rule.MitigationControl)
		compare(source.VulnID, "reference_identifier", source.ReferenceID, rule.ReferenceIdentifier)
		compare(source.VulnID, "srg_id", source.GroupTreeTitle, rule.SRGID)

		if len(rule.GroupTree) == 0 {
			mismatches = append(mismatches, Mismatch{
				VulnID: source.VulnID,
				Field:  "group_tree",
				Want:   "present",
				Got:    "missing",
			})
		} else {
			compare(source.VulnID, "group_tree[0].id", source.VulnID, rule.GroupTree[0].ID)
			compare(source.VulnID, "group_tree[0].title", source.GroupTreeTitle, rule.GroupTree[0].Title)
		}

		if !sameStrings(source.CCIs, rule.CCIs) {
			mismatches = append(mismatches, Mismatch{
				VulnID: source.VulnID,
				Field:  "ccis",
				Want:   strings.Join(source.CCIs, ","),
				Got:    strings.Join(rule.CCIs, ","),
			})
		}
	}

	sort.Slice(mismatches, func(i, j int) bool {
		if mismatches[i].VulnID == mismatches[j].VulnID {
			return mismatches[i].Field < mismatches[j].Field
		}
		return mismatches[i].VulnID < mismatches[j].VulnID
	})
	return mismatches
}

func normalizeText(value string) string {
	value = strings.ReplaceAll(value, "
", "
")
	lines := strings.Split(value, "
")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " 	")
	}
	return strings.TrimSpace(strings.Join(lines, "
"))
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
