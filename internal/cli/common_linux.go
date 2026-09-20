//go:build linux

package cli

import (
	"os"
	"strings"
	"time"

	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/policy"
	"github.com/Exonical/stigctl/internal/rules"
	"github.com/Exonical/stigctl/internal/validation"
)

func outputExtension(format string) string {
	if strings.EqualFold(format, "junit") {
		return "xml"
	}
	return strings.ToLower(format)
}

func writeEffectiveGossVars(
	ruleDoc rules.Document,
	exceptionDoc exceptions.Document,
	profile string,
	hostname string,
) (string, func(), error) {
	file, err := os.CreateTemp("", "stigctl-goss-vars-*.yaml")
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", func() {}, err
	}

	enabled := policy.EnabledRules(ruleDoc, exceptionDoc, policy.Context{
		Profile:  profile,
		Hostname: hostname,
		Now:      time.Now(),
	})
	if err := validation.WriteVars(path, validation.Vars{
		Profile:      profile,
		Hostname:     hostname,
		EnabledRules: enabled,
	}); err != nil {
		_ = os.Remove(path)
		return "", func() {}, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}
