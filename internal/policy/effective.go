package policy

import (
	"time"

	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/rules"
)

func EnabledRules(ruleDoc rules.Document, exceptionDoc exceptions.Document, ctx Context) map[string]bool {
	out := make(map[string]bool, len(ruleDoc.Rules))
	for id, rule := range ruleDoc.Rules {
		enabled := rule.Status == rules.StatusAutomated || rule.Status == rules.StatusTailored
		if exception, ok := exceptionDoc.Exceptions[id]; ok && exception.Applies(exceptions.Context{
			Profile: ctx.Profile,
			Host:    ctx.Hostname,
			Now:     ctx.Now,
		}) {
			enabled = false
		}
		out[id] = enabled
	}
	return out
}

func DefaultContext(profile, hostname string) Context {
	return Context{
		Profile:  profile,
		Hostname: hostname,
		Now:      time.Now(),
	}
}
