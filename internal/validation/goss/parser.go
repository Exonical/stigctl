package goss

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/Exonical/stigctl/internal/results"
)

var vulnIDPattern = regexp.MustCompile(`^V-[0-9]+$`)

func Parse(r io.Reader) ([]results.Result, error) {
	var output Output
	if err := json.NewDecoder(r).Decode(&output); err != nil {
		return nil, fmt.Errorf("decode Goss JSON: %w", err)
	}

	grouped := map[string][]TestResult{}
	for _, test := range output.Results {
		id := vulnID(test)
		if id == "" {
			continue
		}
		grouped[id] = append(grouped[id], test)
	}

	ids := make([]string, 0, len(grouped))
	for id := range grouped {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]results.Result, 0, len(ids))
	for _, id := range ids {
		tests := grouped[id]
		status := results.StatusPass
		allSkipped := true
		var evidence []results.Evidence
		var title string

		for _, test := range tests {
			if title == "" {
				title = test.Title
			}
			if !test.Skipped {
				allSkipped = false
			}
			if !test.Successful && !test.Skipped {
				status = results.StatusFail
			}
			evidence = append(evidence, results.Evidence{
				Type:    test.ResourceType + "." + test.Property,
				Message: test.SummaryLine,
			})
		}

		if allSkipped {
			status = results.StatusSkipped
		}

		out = append(out, results.Result{
			VulnID:         id,
			Title:          title,
			Status:         status,
			FindingDetails: findingDetails(tests),
			Evidence:       evidence,
		})
	}

	return out, nil
}

func vulnID(test TestResult) string {
	if raw, ok := test.Meta["stig_id"]; ok {
		if id := strings.TrimSpace(fmt.Sprint(raw)); vulnIDPattern.MatchString(id) {
			return id
		}
	}
	if vulnIDPattern.MatchString(test.ResourceID) {
		return test.ResourceID
	}
	for _, token := range strings.Fields(test.Title) {
		token = strings.Trim(token, " :-")
		if vulnIDPattern.MatchString(token) {
			return token
		}
	}
	return ""
}

func findingDetails(tests []TestResult) string {
	var lines []string
	for _, test := range tests {
		if test.SummaryLine != "" {
			lines = append(lines, test.SummaryLine)
		}
	}
	return strings.Join(lines, "\n")
}
