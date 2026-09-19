package xccdf

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var tagPattern = regexp.MustCompile(`<[^>]+>`)

type xmlBenchmark struct {
	XMLName xml.Name `xml:"Benchmark"`
	ID      string   `xml:"id,attr"`
	Title   string   `xml:"title"`
	Version string   `xml:"version"`
	Plain   []xmlPlainText `xml:"plain-text"`
	Groups  []xmlGroup `xml:"Group"`
}

type xmlPlainText struct {
	ID   string `xml:"id,attr"`
	Text string `xml:",chardata"`
}

type xmlGroup struct {
	ID          string  `xml:"id,attr"`
	Title       string  `xml:"title"`
	Description string  `xml:"description,innerxml"`
	Rules       []xmlRule `xml:"Rule"`
}

type xmlRule struct {
	ID          string         `xml:"id,attr"`
	Severity    string         `xml:"severity,attr"`
	Weight      string         `xml:"weight,attr"`
	Version     string         `xml:"version"`
	Title       string         `xml:"title"`
	Description string         `xml:"description,innerxml"`
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
	Href string `xml:"href,attr"`
	Text string `xml:",chardata"`
}

func Parse(r io.Reader) (Benchmark, error) {
	var raw xmlBenchmark
	if err := xml.NewDecoder(r).Decode(&raw); err != nil {
		return Benchmark{}, fmt.Errorf("decode XCCDF: %w", err)
	}

	out := Benchmark{
		ID:      raw.ID,
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
			converted := Rule{
				VulnID:      normalizeID(group.ID),
				RuleID:      normalizeRuleID(rule.ID),
				RuleVersion: strings.TrimSpace(rule.Version),
				Title:       strings.TrimSpace(rule.Title),
				GroupTitle:  strings.TrimSpace(group.Title),
				Severity:    strings.TrimSpace(rule.Severity),
				Weight:      strings.TrimSpace(rule.Weight),
				Description: stripTags(rule.Description),
				FixText:     strings.TrimSpace(rule.Fix.Text),
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
				if converted.ReferenceID == "" {
					converted.ReferenceID = strings.TrimSpace(ref.Text)
				}
			}

			out.Rules = append(out.Rules, converted)
		}
	}

	return out, nil
}

func normalizeID(id string) string {
	for _, prefix := range []string{"xccdf_mil.disa.stig_group_", "xccdf_org.ssgproject.content_group_"} {
		id = strings.TrimPrefix(id, prefix)
	}
	return id
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
