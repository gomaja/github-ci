package reports

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gomaja/github-ci/internal/pathpolicy"
)

func countCommandStatus(data []byte) (int, error) {
	var report struct {
		SchemaVersion       string `json:"schema_version"`
		ExecutionSuccessful *bool  `json:"execution_successful"`
	}
	if err := decodeStrictJSON(data, &report); err != nil {
		return 0, err
	}
	if report.SchemaVersion != "1" {
		return 0, fmt.Errorf("unsupported command status schema %q", report.SchemaVersion)
	}
	if report.ExecutionSuccessful == nil {
		return 0, errors.New("command status has no execution_successful value")
	}
	if !*report.ExecutionSuccessful {
		return 1, nil
	}
	return 0, nil
}

func countPathList(data []byte) (int, error) {
	var report struct {
		SchemaVersion string    `json:"schema_version"`
		Paths         *[]string `json:"paths"`
	}
	if err := decodeStrictJSON(data, &report); err != nil {
		return 0, err
	}
	if report.SchemaVersion != "1" {
		return 0, fmt.Errorf("unsupported path-list schema %q", report.SchemaVersion)
	}
	if report.Paths == nil {
		return 0, errors.New("path-list report has no paths array")
	}
	seen := make(map[string]struct{}, len(*report.Paths))
	for index, name := range *report.Paths {
		if err := pathpolicy.Validate("path-list entry", name); err != nil {
			return 0, fmt.Errorf("path %d: %w", index, err)
		}
		if _, exists := seen[name]; exists {
			return 0, fmt.Errorf("duplicate path-list entry %q", name)
		}
		seen[name] = struct{}{}
	}
	return len(*report.Paths), nil
}

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Tests    string       `xml:"tests,attr"`
	Failures string       `xml:"failures,attr"`
	Errors   string       `xml:"errors,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Tests    string `xml:"tests,attr"`
	Failures string `xml:"failures,attr"`
	Errors   string `xml:"errors,attr"`
}

func countJUnit(data []byte) (int, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	var suites junitSuites
	if err := decoder.Decode(&suites); err != nil {
		return 0, fmt.Errorf("decode JUnit report: %w", err)
	}
	if suites.XMLName.Local != "testsuites" {
		return 0, fmt.Errorf("JUnit root must be testsuites, got %q", suites.XMLName.Local)
	}
	tests, err := requiredNonnegative("testsuites tests", suites.Tests)
	if err != nil {
		return 0, err
	}
	failures, err := optionalNonnegative("testsuites failures", suites.Failures)
	if err != nil {
		return 0, err
	}
	errorsCount, err := optionalNonnegative("testsuites errors", suites.Errors)
	if err != nil {
		return 0, err
	}
	findings, ok := addNonnegativeCounts(failures, errorsCount)
	if !ok {
		return 0, errors.New("JUnit failures and errors overflow")
	}
	if findings > tests {
		return 0, errors.New("JUnit failures and errors exceed tests")
	}
	for index, suite := range suites.Suites {
		suiteTests, suiteErr := requiredNonnegative(fmt.Sprintf("testsuite %d tests", index), suite.Tests)
		if suiteErr != nil {
			return 0, suiteErr
		}
		suiteFailures, suiteErr := optionalNonnegative(fmt.Sprintf("testsuite %d failures", index), suite.Failures)
		if suiteErr != nil {
			return 0, suiteErr
		}
		suiteErrors, suiteErr := optionalNonnegative(fmt.Sprintf("testsuite %d errors", index), suite.Errors)
		if suiteErr != nil {
			return 0, suiteErr
		}
		suiteFindings, suiteOK := addNonnegativeCounts(suiteFailures, suiteErrors)
		if !suiteOK {
			return 0, fmt.Errorf("testsuite %d failures and errors overflow", index)
		}
		if suiteFindings > suiteTests {
			return 0, fmt.Errorf("testsuite %d failures and errors exceed tests", index)
		}
	}
	return findings, nil
}

func addNonnegativeCounts(left, right int) (int, bool) {
	if left < 0 || right < 0 {
		return 0, false
	}
	if right > int(^uint(0)>>1)-left {
		return 0, false
	}
	return left + right, true
}

func requiredNonnegative(field, value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("%s attribute is required", field)
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%s must be a nonnegative integer", field)
	}
	return parsed, nil
}

func optionalNonnegative(field, value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	return requiredNonnegative(field, value)
}

var yamllintLine = regexp.MustCompile(`^(.+):([0-9]+):([0-9]+): \[(warning|error)\] .+ \([A-Za-z0-9_-]+\)$`)

func countYamllint(data []byte) (int, error) {
	before, after, ok := bytes.Cut(data, []byte{'\n'})
	if !ok {
		return 0, errors.New("yamllint report has no runner envelope")
	}
	var envelope struct {
		SchemaVersion       string `json:"schema_version"`
		ExecutionSuccessful *bool  `json:"execution_successful"`
	}
	if err := decodeStrictJSON(before, &envelope); err != nil {
		return 0, fmt.Errorf("decode yamllint runner envelope: %w", err)
	}
	if envelope.SchemaVersion != "1" {
		return 0, fmt.Errorf("unsupported yamllint runner envelope schema %q", envelope.SchemaVersion)
	}
	if envelope.ExecutionSuccessful == nil || !*envelope.ExecutionSuccessful {
		return 0, errors.New("yamllint runner execution_successful is not true")
	}
	payload := strings.TrimSuffix(string(after), "\n")
	if payload == "" {
		return 0, nil
	}
	lines := strings.Split(payload, "\n")
	for index, line := range lines {
		match := yamllintLine.FindStringSubmatch(line)
		if match == nil {
			return 0, fmt.Errorf("invalid yamllint finding line %d", index)
		}
		if err := pathpolicy.Validate("yamllint path", match[1]); err != nil {
			return 0, fmt.Errorf("yamllint finding %d: %w", index, err)
		}
	}
	return len(lines), nil
}

func countGopls(data []byte) (int, error) {
	before, after, ok := bytes.Cut(data, []byte{'\n'})
	if !ok {
		return 0, errors.New("gopls report has no runner envelope")
	}
	var envelope struct {
		SchemaVersion       string `json:"schema_version"`
		Parser              string `json:"parser"`
		ExecutionSuccessful *bool  `json:"execution_successful"`
	}
	if err := decodeStrictJSON(before, &envelope); err != nil {
		return 0, fmt.Errorf("decode gopls runner envelope: %w", err)
	}
	if envelope.SchemaVersion != "1" || envelope.Parser != "gopls-diagnostics-v1" {
		return 0, errors.New("unsupported gopls runner envelope")
	}
	if envelope.ExecutionSuccessful == nil || !*envelope.ExecutionSuccessful {
		return 0, errors.New("gopls runner execution_successful is not true")
	}
	payload := strings.TrimSuffix(string(after), "\n")
	if payload == "" {
		return 0, nil
	}
	lines := strings.Split(payload, "\n")
	for index, line := range lines {
		if strings.TrimSpace(line) == "" || strings.ContainsAny(line, "\r\x00") {
			return 0, fmt.Errorf("invalid gopls diagnostic line %d", index)
		}
	}
	return len(lines), nil
}
