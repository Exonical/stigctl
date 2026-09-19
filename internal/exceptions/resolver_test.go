package exceptions

import (
	"testing"
	"time"
)

func TestExceptionAppliesToProfile(t *testing.T) {
	var e Exception
	e.Scope.Profiles = []string{"hpc-compute"}
	e.Lifecycle.Expires = "2027-01-01"

	if !e.Applies(Context{
		Profile: "hpc-compute",
		Now:     time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
	}) {
		t.Fatal("expected exception to apply")
	}
}

func TestExpiredExceptionDoesNotApply(t *testing.T) {
	var e Exception
	e.Scope.All = true
	e.Lifecycle.Expires = "2026-01-01"

	if e.Applies(Context{
		Now: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
	}) {
		t.Fatal("expected expired exception not to apply")
	}
}
