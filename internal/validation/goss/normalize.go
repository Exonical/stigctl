package goss

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Exonical/stigctl/internal/results"
	"github.com/goss-org/goss/resource"
)

func normalizeResults(tests []resource.TestResult) []results.Result {
	grouped := map[string][]resource.TestResult{}
	for _, test := range tests {
		id := vulnIDFromResource(test)
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
		group := grouped[id]
		status := results.StatusPass
		allSkipped := true
		hasFailure := false
		hasError := false
		var evidence []results.Evidence
		var title string
		var details []string

		informativeCommandResult := map[string]bool{}
		for _, test := range group {
			if test.ResourceType == "Command" && test.Property != "exit-status" && test.Result != resource.SKIP {
				informativeCommandResult[test.ResourceId] = true
			}
		}

		for _, test := range group {
			if title == "" {
				title = test.Title
			}
			if !test.Skipped {
				allSkipped = false
			}
			if test.Result == resource.FAIL && test.Err == nil {
				hasFailure = true
			} else if test.Err != nil {
				hasError = true
			}
			message := testMessage(test)
			suppressSuccessfulExitStatus := test.ResourceType == "Command" &&
				test.Property == "exit-status" &&
				test.Result == resource.SUCCESS &&
				informativeCommandResult[test.ResourceId]
			if !suppressSuccessfulExitStatus {
				evidence = append(evidence, results.Evidence{
					Type:    test.ResourceType + "." + test.Property,
					Message: message,
				})
				if message != "" {
					details = append(details, message)
				}
			}
		}

		switch {
		case hasFailure:
			status = results.StatusFail
		case hasError:
			status = results.StatusError
		case allSkipped:
			status = results.StatusSkipped
		}

		out = append(out, results.Result{
			VulnID:         id,
			Title:          title,
			Status:         status,
			FindingDetails: strings.Join(details, "\n"),
			Evidence:       evidence,
		})
	}
	return out
}

func vulnIDFromResource(test resource.TestResult) string {
	if raw, ok := test.Meta["stig_id"]; ok {
		if id := strings.TrimSpace(fmt.Sprint(raw)); vulnIDPattern.MatchString(id) {
			return id
		}
	}
	if vulnIDPattern.MatchString(test.ResourceId) {
		return test.ResourceId
	}
	for _, token := range strings.Fields(test.Title) {
		token = strings.Trim(token, " :-")
		if vulnIDPattern.MatchString(token) {
			return token
		}
	}
	if match := vulnIDPattern.FindString(test.ResourceId); match != "" {
		return match
	}
	return ""
}

func testMessage(test resource.TestResult) string {
	if test.Skipped {
		return fmt.Sprintf("%s: %s: %s: skipped", test.ResourceType, test.ResourceId, test.Property)
	}
	if test.Err != nil {
		return fmt.Sprintf("%s: %s: %s: %s", test.ResourceType, test.ResourceId, test.Property, test.Err.Error())
	}
	if test.Result == resource.SUCCESS {
		return fmt.Sprintf(
			"%s: %s: %s: actual=%v",
			test.ResourceType,
			test.ResourceId,
			test.Property,
			formatMatcherValue(test.MatcherResult.Actual),
		)
	}
	return fmt.Sprintf(
		"%s: %s: %s: expected=%v actual=%v",
		test.ResourceType,
		test.ResourceId,
		test.Property,
		formatMatcherValue(test.MatcherResult.Expected),
		formatMatcherValue(test.MatcherResult.Actual),
	)
}

func formatMatcherValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return "<nil>"
	case string:
		return strings.TrimSuffix(typed, "\n")
	case []byte:
		return strings.TrimSuffix(string(typed), "\n")
	case *bytes.Buffer:
		return strings.TrimSuffix(typed.String(), "\n")
	case interface {
		Size() int64
		ReadAt([]byte, int64) (int, error)
	}:
		size := typed.Size()
		if size == 0 {
			return ""
		}
		buf := make([]byte, int(size))
		n, err := typed.ReadAt(buf, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Sprint(value)
		}
		return strings.TrimSuffix(string(buf[:n]), "\n")
	default:
		return fmt.Sprint(value)
	}
}
