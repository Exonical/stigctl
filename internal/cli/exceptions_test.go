package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestExceptionsLintRejectsUnknownRuleReference(t *testing.T) {
	root := writeExceptionsLintBaseline(t, `schema_version: 1
exceptions:
  V-1:
    status: exception
    scope: {all: true}
    justification: {reason: approved}
    approval: {approved_by: ISSO}
  V-2:
    status: not_applicable
    scope: {all: true}
    justification: {reason: not applicable}
    approval: {approved_by: ISSO}
`)
	previousContentRoot := contentRoot
	contentRoot = root
	defer func() { contentRoot = previousContentRoot }()

	cmd := newExceptionsCommand()
	cmd.SetArgs([]string{"lint", "test:v1"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "V-2") {
		t.Fatalf("Execute() error = %v, want unknown V-2 reference", err)
	}
}

func TestExceptionsLintStrictRejectsWarnings(t *testing.T) {
	root := writeExceptionsLintBaseline(t, `schema_version: 1
exceptions:
  V-1:
    status: exception
    scope: {all: true}
    justification: {reason: approved}
`)
	previousContentRoot := contentRoot
	contentRoot = root
	defer func() { contentRoot = previousContentRoot }()

	var stderr bytes.Buffer
	cmd := newExceptionsCommand()
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"lint", "test:v1", "--strict"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want strict warning failure")
	}
	if !strings.Contains(stderr.String(), "V-1: approval.approved_by is not set") {
		t.Fatalf("stderr = %q, want approval warning", stderr.String())
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

func writeExceptionsLintBaseline(t *testing.T, exceptionsYAML string) string {
	t.Helper()
	root := t.TempDir()
	baselineDir := filepath.Join(root, "stig", "test", "v1")
	if err := os.MkdirAll(baselineDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"manifest.yaml": `schema_version: 1
profile:
  id: test
os:
  family: test
  major_version: 1
baseline:
  authority: test
  version: 1
  release: 1
`,
		"rules.yaml": `schema_version: 1
rules:
  V-1:
    title: test rule
    status: manual
`,
		"exceptions.yaml": exceptionsYAML,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(baselineDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
