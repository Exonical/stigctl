package goss

import (
	"context"
	"fmt"
	"strings"

	"github.com/Exonical/stigctl/internal/results"
	"github.com/Exonical/stigctl/internal/validation"
	gosslib "github.com/goss-org/goss"
	"github.com/goss-org/goss/resource"
	gossutil "github.com/goss-org/goss/util"
)

type Runner struct{}

func New() Runner {
	return Runner{}
}

func (Runner) Validate(ctx context.Context, req validation.Request) ([]results.Result, error) {
	if req.GossFile == "" {
		return nil, fmt.Errorf("goss file is required")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(req.Vars) > 1 {
		return nil, fmt.Errorf("embedded Goss v0.4.10 supports one vars file, got %d", len(req.Vars))
	}

	options := []gossutil.ConfigOption{
		gossutil.WithSpecFile(req.GossFile),
		gossutil.WithPackageManager(req.Package),
		gossutil.WithMaxConcurrency(50),
	}
	if len(req.Vars) == 1 {
		options = append(options, gossutil.WithVarsFile(req.Vars[0]))
	}
	config, err := gossutil.NewConfig(options...)
	if err != nil {
		return nil, fmt.Errorf("configure embedded Goss: %w", err)
	}

	ch, err := gosslib.ValidateResults(config)
	if err != nil {
		return nil, fmt.Errorf("embedded Goss validation setup failed: %w", err)
	}

	var tests []resource.TestResult
	for batch := range ch {
		tests = append(tests, batch...)
	}
	return normalizeResults(tests), nil
}

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
	sortStrings(ids)

	out := make([]results.Result, 0, len(ids))
	for _, id := range ids {
		group := grouped[id]
		status := results.StatusPass
		allSkipped := true
		var evidence []results.Evidence
		var title string
		var details []string

		for _, test := range group {
			if title == "" {
				title = test.Title
			}
			if !test.Skipped {
				allSkipped = false
			}
			if test.Result == resource.FAIL {
				status = results.StatusFail
			}
			message := testMessage(test)
			evidence = append(evidence, results.Evidence{
				Type:    test.ResourceType + "." + test.Property,
				Message: message,
			})
			if test.Result == resource.FAIL || test.Err != nil {
				if message != "" {
					details = append(details, message)
				}
			}
		}

		if allSkipped {
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
		return fmt.Sprintf("%s: %s: %s: matches expectation", test.ResourceType, test.ResourceId, test.Property)
	}
	return fmt.Sprintf(
		"%s: %s: %s: expected=%v actual=%v",
		test.ResourceType,
		test.ResourceId,
		test.Property,
		test.MatcherResult.Expected,
		test.MatcherResult.Actual,
	)
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
