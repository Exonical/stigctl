package junit

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	stigexport "github.com/Exonical/stigctl/internal/export"
	"github.com/Exonical/stigctl/internal/results"
)

type Exporter struct{}

type testSuite struct {
	XMLName  xml.Name   `xml:"testsuite"`
	Name     string     `xml:"name,attr"`
	Hostname string     `xml:"hostname,attr,omitempty"`
	Tests    int        `xml:"tests,attr"`
	Failures int        `xml:"failures,attr"`
	Errors   int        `xml:"errors,attr"`
	Skipped  int        `xml:"skipped,attr"`
	Cases    []testCase `xml:"testcase"`
}

type testCase struct {
	Name      string       `xml:"name,attr"`
	Classname string       `xml:"classname,attr"`
	Failure   *testFailure `xml:"failure,omitempty"`
	Error     *testError   `xml:"error,omitempty"`
	Skipped   *testSkipped `xml:"skipped,omitempty"`
	SystemOut string       `xml:"system-out,omitempty"`
}

type testFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type testError struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type testSkipped struct {
	Message string `xml:"message,attr"`
}

func (Exporter) Export(ctx context.Context, writer io.Writer, req stigexport.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	suite := testSuite{
		Name: req.Baseline, Hostname: req.Target.Hostname, Tests: len(req.Results),
		Cases: make([]testCase, 0, len(req.Results)),
	}
	for _, result := range req.Results {
		if err := ctx.Err(); err != nil {
			return err
		}
		item := testCase{
			Name:      result.VulnID + " - " + result.Title,
			Classname: "stigctl." + req.Baseline + "." + result.Severity,
			SystemOut: details(result),
		}
		switch result.Status {
		case results.StatusFail:
			suite.Failures++
			item.Failure = &testFailure{
				Message: result.VulnID + " is an open STIG finding",
				Type:    "stig_finding",
				Body:    findingDetails(result),
			}
		case results.StatusError:
			suite.Errors++
			item.Error = &testError{
				Message: result.VulnID + " could not be validated",
				Type:    "validation_error",
				Body:    findingDetails(result),
			}
		case results.StatusSkipped, results.StatusNotApplicable, results.StatusException, results.StatusManual:
			suite.Skipped++
			item.Skipped = &testSkipped{Message: skippedMessage(result.Status)}
		}
		suite.Cases = append(suite.Cases, item)
	}

	if _, err := io.WriteString(writer, xml.Header); err != nil {
		return fmt.Errorf("write JUnit header: %w", err)
	}
	encoder := xml.NewEncoder(writer)
	encoder.Indent("", "  ")
	if err := encoder.Encode(suite); err != nil {
		return fmt.Errorf("encode JUnit report: %w", err)
	}
	return nil
}

func findingDetails(result results.Result) string {
	if result.FindingDetails != "" {
		return result.FindingDetails
	}
	return result.VulnID + " did not satisfy the expected STIG state."
}

func details(result results.Result) string {
	parts := []string{
		"Vulnerability ID: " + result.VulnID,
		"Rule ID: " + result.RuleID,
		"Severity: " + result.Severity,
		"Status: " + string(result.Status),
	}
	if result.Comments != "" {
		parts = append(parts, "Comments: "+result.Comments)
	}
	for _, evidence := range result.Evidence {
		parts = append(parts, "Evidence ("+evidence.Type+"): "+evidence.Message)
	}
	return strings.Join(parts, "\n")
}

func skippedMessage(status results.Status) string {
	switch status {
	case results.StatusManual:
		return "manual review required"
	case results.StatusNotApplicable:
		return "not applicable"
	case results.StatusException:
		return "approved exception"
	default:
		return "skipped"
	}
}
