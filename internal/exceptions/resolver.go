package exceptions

import (
	"strings"
	"time"
)

type Context struct {
	Profile string
	Host    string
	Now     time.Time
}

func (e Exception) Applies(ctx Context) bool {
	if e.Status != "" && !strings.EqualFold(e.Status, "exception") {
		return false
	}
	if !e.Active(ctx.Now) {
		return false
	}
	if e.Scope.All {
		return true
	}
	if containsFold(e.Scope.Profiles, ctx.Profile) {
		return true
	}
	if containsFold(e.Scope.Hosts, ctx.Host) {
		return true
	}
	return false
}

func (e Exception) Active(now time.Time) bool {
	if e.Lifecycle.Expires == "" {
		return true
	}
	if now.IsZero() {
		now = time.Now()
	}
	expires, err := time.Parse("2006-01-02", e.Lifecycle.Expires)
	if err != nil {
		return false
	}
	return !now.After(expires.Add(24*time.Hour - time.Nanosecond))
}

func containsFold(values []string, want string) bool {
	if want == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
