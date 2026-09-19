package xccdf

import (
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"
)

var tagPattern = regexp.MustCompile(`<[^>]+>`)

type xmlBenchmark struct {
	XMLName xml.Name       `xml:"Benchmark"`
	ID      string         `xml:"id,attr"`
	Title   string         `xml:"title"`
	Version string         `xml:"version"`
	Plain   []xmlPlainText `xml:"plain-text"`
	Groups  []xmlGroup     `xml:"Group"`
}

type xmlPlainText struct {
	ID   string `xml:"id,attr"`
	Text string `xml:",chardata"`
}

type xmlGroup struct {
	ID    string    `xml:"id,attr"`
	Title string    `xml:"title"`
	Rules []xmlRule `xml:"Rule"`
}

type xmlRule struct {
	ID          string         `xml:"id,attr"`
	Severity    string         `xml:"severity,attr"`
	Weight      string         `xml:"weight,attr"`
	Version     string         `xml:"version"`
	Title       string         `xml:"title"`
	Description xmlRichText    `xml:"description"`
	Checks      []xmlCheck     `xml:"check"`
	FixText     xmlFixText     `xml:"fixtext"`
	Fix         xmlFix         `xml:"fix"`
	Idents      []xmlIdent     `xml:"ident"`
	References  []xmlReference `xml:"reference"`
}

type xmlRichText struct {
	Inner string `xml:",innerxml"`
}

type xmlCheck struct {
	System  string      `xml:"system,attr"`
	Content string      `xml:"check-content"`
	Ref     xmlCheckRef `xml:"check-content-ref"`
	Text    string      `xml:",chardata"`
}

type xmlCheckRef struct {
	Href string `xml:"href,attr"`
	Name string `xml:"name,attr"`
}

type xmlFixText struct {
	FixRef string `xml:"fixref,attr"`
	Text   string `xml:",chardata"`
}

type xmlFix struct {
	ID   string `xml:"id,attr"`
	Text string `xml:",chardata"`
}

type xmlIdent struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

type xmlReference struct {
	Identifier string `xml:"identifier"`
}

func Parse(r io.Reader) (Benchmark, error) {
	var raw xmlBenchmark
	if err := xml.NewDecoder(r).Decode(&raw); err != nil {
		return Benchmark{}, fmt.Errorf("decode XCCDF: %w", err)
	}

	out := Benchmark{
		ID:      normalizeBenchmarkID(raw.ID),
		Title:   strings.TrimSpace(raw.Title),
		Version: strings.TrimSpace(raw.Version),
	}
	for _, p := range raw.Plain {
		if strings.EqualFold(p.ID, "release-info") {
			out.ReleaseInfo = strings.TrimSpace(p.Text)
			break
		}
	}

	for _, group := range raw.Groups {
		for _, rule := range group.Rules {
			description := parseDescription(rule.Description.Inner)
			converted := Rule{
				VulnID:                   normalizeID(group.ID),
				RuleID:                   normalizeRuleID(rule.ID),
				RuleIDSrc:                normalizeRuleIDSource(rule.ID),
				RuleVersion:              strings.TrimSpace(rule.Version),
				Title:                    strings.TrimSpace(rule.Title),
				GroupTitle:               strings.TrimSpace(rule.Title),
				GroupTreeTitle:           strings.TrimSpace(group.Title),
				Severity:                 strings.TrimSpace(rule.Severity),
				Weight:                   strings.TrimSpace(rule.Weight),
				Description:              description.All,
				Discussion:               description.VulnDiscussion,
				FalsePositives:           description.FalsePositives,
				FalseNegatives:           description.FalseNegatives,
				Documentable:             description.Documentable,
				Mitigations:              description.Mitigations,
				SecurityOverrideGuidance: description.SeverityOverrideGuidance,
				PotentialImpacts:         description.PotentialImpacts,
				ThirdPartyTools:          description.ThirdPartyTools,
				MitigationControl:        description.MitigationControl,
				Responsibility:           description.Responsibility,
				IAControls:               description.IAControls,
				FixText:                  strings.TrimSpace(rule.FixText.Text),
			}
			if converted.FixText == "" {
				converted.FixText = strings.TrimSpace(rule.Fix.Text)
			}

			if len(rule.Checks) > 0 {
				check := rule.Checks[0]
				converted.CheckContent = strings.TrimSpace(check.Content)
				if converted.CheckContent == "" {
					converted.CheckContent = strings.TrimSpace(check.Text)
				}
				converted.CheckRefHref = check.Ref.Href
				converted.CheckRefName = check.Ref.Name
				if converted.CheckRefName == "" {
					converted.CheckRefName = check.System
				}
			}

			for _, ident := range rule.Idents {
				value := strings.TrimSpace(ident.Value)
				if strings.Contains(strings.ToLower(ident.System), "cci") || strings.HasPrefix(value, "CCI-") {
					converted.CCIs = append(converted.CCIs, value)
				} else if value != "" {
					converted.LegacyIDs = append(converted.LegacyIDs, value)
				}
			}
			for _, ref := range rule.References {
				if converted.ReferenceID == "" && strings.TrimSpace(ref.Identifier) != "" {
					converted.ReferenceID = strings.TrimSpace(ref.Identifier)
				}
			}

			out.Rules = append(out.Rules, converted)
		}
	}

	return out, nil
}

type descriptionFields struct {
	All                      string
	VulnDiscussion           string
	FalsePositives           string
	FalseNegatives           string
	Documentable             string
	Mitigations              string
	SeverityOverrideGuidance string
	PotentialImpacts         string
	ThirdPartyTools          string
	MitigationControl        string
	Responsibility           string
	IAControls               string
}

func parseDescription(raw string) descriptionFields {
	decoded := html.UnescapeString(raw)
	return descriptionFields{
		All:                      stripTags(decoded),
		VulnDiscussion:           extractTag(decoded, "VulnDiscussion"),
		FalsePositives:           extractTag(decoded, "FalsePositives"),
		FalseNegatives:           extractTag(decoded, "FalseNegatives"),
		Documentable:             extractTag(decoded, "Documentable"),
		Mitigations:              extractTag(decoded, "Mitigations"),
		SeverityOverrideGuidance: extractTag(decoded, "SeverityOverrideGuidance"),
		PotentialImpacts:         extractTag(decoded, "PotentialImpacts"),
		ThirdPartyTools:          extractTag(decoded, "ThirdPartyTools"),
		MitigationControl:        extractTag(decoded, "MitigationControl"),
		Responsibility:           extractTag(decoded, "Responsibility"),
		IAControls:               extractTag(decoded, "IA_Controls"),
	}
}

func extractTag(value, name string) string {
	re := regexp.MustCompile(`(?s)<` + regexp.QuoteMeta(name) + `>(.*?)</` + regexp.QuoteMeta(name) + `>`)
	match := re.FindStringSubmatch(value)
	if len(match) != 2 {
		return ""
	}
	return stripTags(match[1])
}

func normalizeBenchmarkID(id string) string {
	return strings.TrimPrefix(id, "xccdf_mil.disa.stig_benchmark_")
}

func normalizeID(id string) string {
	for _, prefix := range []string{"xccdf_mil.disa.stig_group_", "xccdf_org.ssgproject.content_group_"} {
		id = strings.TrimPrefix(id, prefix)
	}
	return id
}

func normalizeRuleIDSource(id string) string {
	return strings.TrimPrefix(id, "xccdf_mil.disa.stig_rule_")
}

func normalizeRuleID(id string) string {
	for _, prefix := range []string{"xccdf_mil.disa.stig_rule_", "xccdf_org.ssgproject.content_rule_"} {
		id = strings.TrimPrefix(id, prefix)
	}
	return strings.TrimSuffix(id, "_rule")
}

func stripTags(s string) string {
	s = tagPattern.ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(s), " ")
}
