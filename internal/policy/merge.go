package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/results"
	"github.com/Exonical/stigctl/internal/rules"
)

type Context struct {
	Profile  string
	Hostname string
	Now      time.Time
}

func Merge(ruleDoc rules.Document, exceptionDoc exceptions.Document, scanned []results.Result, ctx Context) []results.Result {
	scannedByID := make(map[string]results.Result, len(scanned))
	for _, result := range scanned {
		scannedByID[result.VulnID] = result
	}

	ids := make([]string, 0, len(ruleDoc.Rules))
	for id := range ruleDoc.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]results.Result, 0, len(ids))
	for _, id := range ids {
		rule := ruleDoc.Rules[id]
		result, found := scannedByID[id]
		if !found {
			result = results.Result{VulnID: id}
		}
		result.RuleID = rule.RuleID
		result.Title = rule.Title
		result.Severity = rule.Severity

		if exception, ok := exceptionDoc.Exceptions[id]; ok && exception.Applies(exceptions.Context{
			Profile: ctx.Profile,
			Host:    ctx.Hostname,
			Now:     ctx.Now,
		}) {
			switch strings.ToLower(exception.Status) {
			case "not_applicable", "not-applicable", "n/a":
				result.Status = results.StatusNotApplicable
				result.Comments = exceptionComment(exception)
				if result.FindingDetails == "" {
					result.FindingDetails = "Rule is not applicable for this target by approved policy."
				}
			default:
				result.Status = results.StatusException
				result.Comments = exceptionComment(exception)
				if result.FindingDetails == "" {
					result.FindingDetails = "Rule has an approved organizational exception; technical compliance was not asserted."
				}
			}
			out = append(out, result)
			delete(scannedByID, id)
			continue
		}

		switch rule.Status {
		case rules.StatusManual:
			result.Status = results.StatusManual
		case rules.StatusNotApplicable:
			result.Status = results.StatusNotApplicable
		case rules.StatusAutomated, rules.StatusTailored:
			if !found {
				result.Status = results.StatusError
				result.FindingDetails = "No Goss result was produced for this automated rule."
			}
		default:
			if !found {
				result.Status = results.StatusError
				result.FindingDetails = "Rule has no recognized implementation status."
			}
		}

		out = append(out, result)
		delete(scannedByID, id)
	}

	// Preserve Goss tests that are already tagged with a V-ID but have not yet
	// been added to rules.yaml. This makes incremental baseline development useful.
	remaining := make([]string, 0, len(scannedByID))
	for id := range scannedByID {
		remaining = append(remaining, id)
	}
	sort.Strings(remaining)
	for _, id := range remaining {
		out = append(out, scannedByID[id])
	}

	return out
}

func exceptionComment(exception exceptions.Exception) string {
	label := "Approved exception"
	if strings.EqualFold(exception.Status, "not_applicable") || strings.EqualFold(exception.Status, "not-applicable") {
		label = "Approved not applicable"
	}
	parts := []string{label}
	if exception.Approval.Ticket != "" {
		parts = append(parts, "ticket="+exception.Approval.Ticket)
	}
	if exception.Lifecycle.Expires != "" {
		parts = append(parts, "expires="+exception.Lifecycle.Expires)
	}
	if exception.Justification.Reason != "" {
		parts = append(parts, "reason="+exception.Justification.Reason)
	}
	return strings.Join(parts, "; ")
}

func HasFailures(items []results.Result) bool {
	for _, item := range items {
		if item.Status == results.StatusFail || item.Status == results.StatusError {
			return true
		}
	}
	return false
}

func Summary(items []results.Result) string {
	counts := map[results.Status]int{}
	for _, item := range items {
		counts[item.Status]++
	}
	return fmt.Sprintf(
		"pass=%d fail=%d exception=%d not_applicable=%d manual=%d skipped=%d error=%d",
		counts[results.StatusPass],
		counts[results.StatusFail],
		counts[results.StatusException],
		counts[results.StatusNotApplicable],
		counts[results.StatusManual],
		counts[results.StatusSkipped],
		counts[results.StatusError],
	)
}
