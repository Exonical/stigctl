//go:build linux

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyDryRunListsStepsWithoutExecuting(t *testing.T) {
	firstOutput := filepath.Join(t.TempDir(), "first")
	secondOutput := filepath.Join(t.TempDir(), "second")
	root := writeApplyBaseline(t, false, firstOutput, secondOutput)
	setApplyTestEnvironment(t, root, true)

	stdout, stderr, err := executeApply(t, "n\n", "test:v1", "--dry-run")
	if err != nil {
		t.Fatalf("apply --dry-run error = %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want no prompt", stderr)
	}
	firstIndex := strings.Index(stdout, "V-1  remediation/00-first.yaml")
	secondIndex := strings.Index(stdout, "V-2  remediation/10-second.yaml")
	if firstIndex < 0 || secondIndex < 0 || firstIndex >= secondIndex {
		t.Fatalf("plan does not preserve step order:\n%s", stdout)
	}
	for _, path := range []string{firstOutput, secondOutput} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("dry run created %s", path)
		}
	}
}

func TestApplyDryRunRulesSelection(t *testing.T) {
	root := writeApplyBaseline(t, false, filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second"))
	setApplyTestEnvironment(t, root, false)

	stdout, _, err := executeApply(t, "", "test:v1", "--dry-run", "--rules", "V-2")
	if err != nil {
		t.Fatalf("apply --rules error = %v", err)
	}
	if strings.Contains(stdout, "V-1  ") || !strings.Contains(stdout, "V-2  remediation/10-second.yaml") {
		t.Fatalf("unexpected selected-rule plan:\n%s", stdout)
	}
}

func TestApplyRejectsUnknownRule(t *testing.T) {
	root := writeApplyBaseline(t, false, filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second"))
	setApplyTestEnvironment(t, root, false)

	_, _, err := executeApply(t, "", "test:v1", "--dry-run", "--rules", "V-999")
	if err == nil || !strings.Contains(err.Error(), "unknown rule V-999") {
		t.Fatalf("error = %v, want unknown rule", err)
	}
}

func TestApplyRejectsRuleWithoutRemediation(t *testing.T) {
	root := writeApplyBaseline(t, false, filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second"))
	setApplyTestEnvironment(t, root, false)

	_, _, err := executeApply(t, "", "test:v1", "--dry-run", "--rules", "V-3")
	if err == nil || !strings.Contains(err.Error(), "rule V-3 has no remediation mapping") {
		t.Fatalf("error = %v, want missing remediation mapping", err)
	}
}

func TestApplyDryRunPolicyAndIgnoreExceptions(t *testing.T) {
	root := writeApplyBaseline(t, true, filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second"))
	setApplyTestEnvironment(t, root, false)

	stdout, _, err := executeApply(t, "", "test:v1", "--dry-run")
	if err != nil {
		t.Fatalf("apply policy dry run error = %v", err)
	}
	if strings.Contains(stdout, "V-1  remediation") || !strings.Contains(stdout, "skipping remediation V-1 due to effective policy") {
		t.Fatalf("policy did not exclude V-1:\n%s", stdout)
	}
	if !strings.Contains(stdout, "skipped by policy: 1") {
		t.Fatalf("policy summary missing:\n%s", stdout)
	}

	stdout, _, err = executeApply(t, "", "test:v1", "--dry-run", "--ignore-exceptions")
	if err != nil {
		t.Fatalf("apply --ignore-exceptions error = %v", err)
	}
	if !strings.Contains(stdout, "V-1  remediation/00-first.yaml") {
		t.Fatalf("ignored exception still excluded V-1:\n%s", stdout)
	}
}

func TestApplyPromptCancellationAndConfirmation(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "cancelled")
		root := writeApplyBaseline(t, false, output, filepath.Join(t.TempDir(), "second"))
		setApplyTestEnvironment(t, root, true)

		_, stderr, err := executeApply(t, "n\n", "test:v1", "--rules", "V-1")
		if err == nil || !strings.Contains(err.Error(), "apply cancelled") {
			t.Fatalf("error = %v, want cancellation", err)
		}
		if !strings.Contains(stderr, "apply 1 remediation step(s)") {
			t.Fatalf("stderr = %q, want prompt", stderr)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("cancelled apply created %s", output)
		}
	})

	t.Run("confirm", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "confirmed")
		root := writeApplyBaseline(t, false, output, filepath.Join(t.TempDir(), "second"))
		setApplyTestEnvironment(t, root, true)

		_, _, err := executeApply(t, "yes\n", "test:v1", "--rules", "V-1")
		if err != nil {
			t.Fatalf("confirmed apply error = %v", err)
		}
		if _, err := os.Stat(output); err != nil {
			t.Fatalf("confirmed apply did not create %s: %v", output, err)
		}
	})
}

func TestApplyYesSkipsTerminalPrompt(t *testing.T) {
	output := filepath.Join(t.TempDir(), "yes")
	root := writeApplyBaseline(t, false, output, filepath.Join(t.TempDir(), "second"))
	setApplyTestEnvironment(t, root, true)

	_, stderr, err := executeApply(t, "", "test:v1", "--rules", "V-1", "--yes")
	if err != nil {
		t.Fatalf("apply --yes error = %v", err)
	}
	if strings.Contains(stderr, "[y/N]") {
		t.Fatalf("stderr contains prompt: %q", stderr)
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("apply --yes did not create %s: %v", output, err)
	}
}

func executeApply(t *testing.T, input string, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := newApplyCommand()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func setApplyTestEnvironment(t *testing.T, root string, terminal bool) {
	t.Helper()
	previousContentRoot := contentRoot
	previousTerminal := stdinIsTerminal
	contentRoot = root
	stdinIsTerminal = func() bool { return terminal }
	t.Cleanup(func() {
		contentRoot = previousContentRoot
		stdinIsTerminal = previousTerminal
	})
}

func writeApplyBaseline(t *testing.T, exceptV1 bool, firstOutput, secondOutput string) string {
	t.Helper()
	root := t.TempDir()
	baselineDir := filepath.Join(root, "stig", "test", "v1")
	remediationDir := filepath.Join(baselineDir, "remediation")
	profileDir := filepath.Join(root, "profiles")
	for _, dir := range []string{remediationDir, profileDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	exceptionsYAML := "schema_version: 1\nexceptions: {}\n"
	if exceptV1 {
		exceptionsYAML = `schema_version: 1
exceptions:
  V-1:
    status: exception
    scope: {all: true}
    justification: {reason: approved}
    approval: {approved_by: ISSO}
`
	}
	files := map[string]string{
		filepath.Join(profileDir, "default.yaml"): "schema_version: 1\nprofile:\n  id: default\n  name: Default\n",
		filepath.Join(baselineDir, "manifest.yaml"): `schema_version: 1
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
		filepath.Join(baselineDir, "rules.yaml"): `schema_version: 1
rules:
  V-1:
    title: first
    status: automated
    remediation:
      file: remediation/00-first.yaml
      step: V-1
  V-2:
    title: second
    status: automated
    remediation:
      file: remediation/10-second.yaml
      step: V-2
  V-3:
    title: manual
    status: manual
`,
		filepath.Join(baselineDir, "exceptions.yaml"):   exceptionsYAML,
		filepath.Join(remediationDir, "00-first.yaml"):  fmt.Sprintf("stages:\n  stig:\n    - name: V-1\n      commands:\n        - %q\n", "touch "+firstOutput),
		filepath.Join(remediationDir, "10-second.yaml"): fmt.Sprintf("stages:\n  stig:\n    - name: V-2\n      commands:\n        - %q\n", "touch "+secondOutput),
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
