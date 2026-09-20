package cli

import (
	"reflect"
	"testing"

	"github.com/Exonical/stigctl/internal/exceptions"
)

func TestExceptionListRowsExpandAndSortScopes(t *testing.T) {
	var profileException exceptions.Exception
	profileException.Status = "exception"
	profileException.Scope.Profiles = []string{"workstation", "server"}
	profileException.Justification.Reason = "profile reason"

	var globalException exceptions.Exception
	globalException.Status = "not_applicable"
	globalException.Scope.All = true

	var hostException exceptions.Exception
	hostException.Status = "exception"
	hostException.Scope.Hosts = []string{"node01"}

	doc := exceptions.Document{Exceptions: map[string]exceptions.Exception{
		"V-3": hostException,
		"V-2": globalException,
		"V-1": profileException,
	}}
	rows := exceptionListRows(doc, "")
	got := make([]string, 0, len(rows))
	for _, row := range rows {
		got = append(got, row.Scope+"/"+row.VulnID)
	}
	want := []string{
		"all/V-2",
		"host:node01/V-3",
		"server/V-1",
		"workstation/V-1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
}

func TestExceptionListRowsFilterProfileAndIncludeGlobal(t *testing.T) {
	var serverException exceptions.Exception
	serverException.Scope.Profiles = []string{"server"}
	var workstationException exceptions.Exception
	workstationException.Scope.Profiles = []string{"workstation"}
	var globalException exceptions.Exception
	globalException.Scope.All = true
	var hostException exceptions.Exception
	hostException.Scope.Hosts = []string{"node01"}

	doc := exceptions.Document{Exceptions: map[string]exceptions.Exception{
		"V-1": serverException,
		"V-2": workstationException,
		"V-3": globalException,
		"V-4": hostException,
	}}
	rows := exceptionListRows(doc, "SERVER")
	got := make([]string, 0, len(rows))
	for _, row := range rows {
		got = append(got, row.Scope+"/"+row.VulnID)
	}
	want := []string{"all/V-3", "server/V-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
}
