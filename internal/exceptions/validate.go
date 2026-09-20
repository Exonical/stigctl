package exceptions

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Exonical/stigctl/internal/rules"
)

const dateLayout = "2006-01-02"

var vulnIDPattern = regexp.MustCompile(`^V-[0-9]+$`)

func Validate(doc Document, now time.Time) (warnings []string, err error) {
	ids := make([]string, 0, len(doc.Exceptions))
	for id := range doc.Exceptions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var errs []error
	for _, id := range ids {
		exception := doc.Exceptions[id]
		addError := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("%s: %s", id, fmt.Sprintf(format, args...)))
		}

		if !vulnIDPattern.MatchString(id) {
			addError("invalid V-ID")
		}
		if !strings.EqualFold(exception.Status, "exception") && !strings.EqualFold(exception.Status, "not_applicable") {
			addError("status must be exception or not_applicable")
		}
		if strings.TrimSpace(exception.Justification.Reason) == "" {
			addError("justification.reason is required")
		}
		if !exception.Scope.All && len(exception.Scope.Profiles) == 0 && len(exception.Scope.Hosts) == 0 {
			addError("scope must set all, profiles, or hosts")
		}
		if exception.Lifecycle.ReviewIntervalDays < 0 {
			addError("lifecycle.review_interval_days must be at least 0")
		}

		created, createdOK := validateDate(id, "lifecycle.created", exception.Lifecycle.Created, &errs)
		expires, expiresOK := validateDate(id, "lifecycle.expires", exception.Lifecycle.Expires, &errs)
		_, _ = validateDate(id, "approval.approved_date", exception.Approval.ApprovedDate, &errs)
		if createdOK && expiresOK && expires.Before(created) {
			addError("lifecycle.expires must not be before lifecycle.created")
		}

		if strings.TrimSpace(exception.Approval.ApprovedBy) == "" {
			warnings = append(warnings, fmt.Sprintf("%s: approval.approved_by is not set", id))
		}
		if expiresOK && !now.IsZero() && now.After(expires.AddDate(0, 0, 1).Add(-time.Nanosecond)) {
			warnings = append(warnings, fmt.Sprintf(
				"%s: exception expired on %s; the rule will be evaluated normally",
				id,
				exception.Lifecycle.Expires,
			))
		}
		if createdOK && exception.Lifecycle.ReviewIntervalDays > 0 && !now.IsZero() {
			reviewDue := created.AddDate(0, 0, exception.Lifecycle.ReviewIntervalDays)
			if now.After(reviewDue) {
				warnings = append(warnings, fmt.Sprintf("%s: review overdue since %s", id, reviewDue.Format(dateLayout)))
			}
		}
	}

	return warnings, errors.Join(errs...)
}

func CheckRuleReferences(doc Document, ruleDoc rules.Document) error {
	ids := make([]string, 0, len(doc.Exceptions))
	for id := range doc.Exceptions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var errs []error
	for _, id := range ids {
		if _, ok := ruleDoc.Rules[id]; !ok {
			errs = append(errs, fmt.Errorf("%s: exception references a rule not present in rules.yaml", id))
		}
	}
	return errors.Join(errs...)
}

func validateDate(id, field, value string, errs *[]error) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(dateLayout, value)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %s must use YYYY-MM-DD", id, field))
		return time.Time{}, false
	}
	return parsed, true
}
