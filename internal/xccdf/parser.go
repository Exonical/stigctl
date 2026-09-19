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
	ID          string    `xml:"id,attr"`
	Title       string    `xml:"title"`
	Description string    `xml:"description"`
	Rules       []xmlRule `xml:"Rule"`
}

type xmlRule struct {
	ID          string         `xml:"id,attr"`
	Severity    string         `xml:"severity,attr"`
	Weight      string         `xml:"weight,attr"`
	Version     string         `xml:"version"`
	Title       string         `xml:"title"`
	Description string         `xml:"description"`
	Checks      []xmlCheck     `xml:"check"`
	Fix         xmlFix         `xml:"fix"`
	Idents      []xmlIdent     `xml:"ident"`
	References  []xmlReference `xml:"reference"`
}

type xmlCheck struct {
	Content string      `xml:"check-content"`
	Ref     xmlCheckRef `xml:"check-content-ref"`
}

type xmlCheckRef struct {
	Href string `xml:"href,attr"`
	Name string `xml:"name,attr"`
}

type xmlFix struct {
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
			description := parseDescription(rule.Description)
			converted := Rule{
				VulnID:                  normalizeID(group.ID),
				RuleID:                  normalizeRuleID(rule.ID),
				RuleIDSrc:               normalizeRuleIDSource(rule.ID),
				RuleVersion:             strings.TrimSpace(rule.Version),
				Title:                   strings.TrimSpace(rule.Title),
				GroupTitle:              strings.TrimSpace(rule.Title),
				GroupTreeTitle:          strings.TrimSpace(group.Title),
				Severity:                strings.TrimSpace(rule.Severity),
				Weight:                  strings.TrimSpace(rule.Weight),
				Description:             description.All,
				Discussion:              description.VulnDiscussion,
				FalsePositives:          description.FalsePositives,
				FalseNegatives:          description.FalseNegatives,
				Documentable:            description.Documentable,
				Mitigations:             description.Mitigations,
				SecurityOverrideGuidance: description.SeverityOverrideGuidance,
				PotentialImpacts:        description.PotentialImpacts,
				ThirdPartyTools:         description.ThirdPartyTools,
				MitigationControl:       description.MitigationControl,
				Responsibility:          description.Responsibility,
				IAControls:              description.IAControls,
				FixText:                 strings.TrimSpace(rule.Fix.Text),
			}
			if len(rule.Checks) > 0 {
				converted.CheckContent = strings.TrimSpace(rule.Checks[0].Content)
				converted.CheckRefHref = rule.Checks[0].Ref.Href
				converted.CheckRefName = rule.Checks[0].Ref.Name
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
	Mitigations               string
	SeverityOverrideGuidance string
	PotentialImpacts          string
	ThirdPartyTools           string
	MitigationControl        string
	Responsibility            string
	IAControls                string
}

func parseDescription(raw string) descriptionFields {
	decoded := html.UnescapeString(raw)
	return descriptionFields{
		All:                      stripTags(decoded),
		VulnDiscussion:           extractTag(decoded, "VulnDiscussion"),
		FalsePositives:           extractTag(decoded, "FalsePositives"),
		FalseNegatives:           extractTag(decoded, "FalseNegatives"),
		Documentable:             extractTag(decoded, "Documentable"),
		Mitigations:               extractTag(decoded, "Mitigations"),
		SeverityOverrideGuidance: extractTag(decoded, "SeverityOverrideGuidance"),
		PotentialImpacts:          extractTag(decoded, "PotentialImpacts"),
		ThirdPartyTools:           extractTag(decoded, "ThirdPartyTools"),
		MitigationControl:        extractTag(decoded, "MitigationControl"),
		Responsibility:            extractTag(decoded, "Responsibility"),
		IAControls:                extractTag(decoded, "IAControls"),
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
