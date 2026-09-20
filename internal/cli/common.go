package cli

import (
	"os"
	"time"

	"github.com/Exonical/stigctl/internal/exceptions"
	"github.com/Exonical/stigctl/internal/policy"
	stigprofile "github.com/Exonical/stigctl/internal/profile"
	"github.com/Exonical/stigctl/internal/rules"
	"github.com/Exonical/stigctl/internal/validation"
)

func validateProfile(id string) error {
	_, err := stigprofile.NewStore(contentRoot).Resolve(id)
	return err
}

func writeEffectiveGossVars(
	ruleDoc rules.Document,
	exceptionDoc exceptions.Document,
	profile string,
	hostname string,
	checkScript string,
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
		CheckScript:  checkScript,
		EnabledRules: enabled,
	}); err != nil {
		_ = os.Remove(path)
		return "", func() {}, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}
