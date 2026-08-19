package gate

import (
	"slices"
	"strings"
	"testing"

	"github.com/gomaja/github-ci/internal/evidence"
	"github.com/gomaja/github-ci/internal/exceptions"
)

func TestValidateRecordAgainstExpectedChecksIdentityFieldsIndependently(t *testing.T) {
	input := validInput(t)
	tests := []struct {
		name   string
		mutate func(*evidence.Record)
	}{
		{name: "tool", mutate: func(record *evidence.Record) { record.Tool = "semgrep" }},
		{name: "command", mutate: func(record *evidence.Record) { record.CommandID = "staticcheck/other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := input.Records[0]
			test.mutate(&record)
			findings := validateRecordAgainstExpected(input.Plan, input.Plan.Expected[0], record)
			assertFindingCodes(t, findings, "identity-mismatch")
		})
	}
}

func TestValidateRecordAgainstExpectedChecksNotApplicableFieldsIndependently(t *testing.T) {
	input := validNotApplicableInput(t)
	tests := []struct {
		name   string
		mutate func(*evidence.Record)
	}{
		{name: "outcome", mutate: func(record *evidence.Record) { record.Outcome = evidence.OutcomePass }},
		{name: "exit code", mutate: func(record *evidence.Record) { record.ExitCode = 1 }},
		{name: "finding count", mutate: func(record *evidence.Record) { record.FindingCount = 1 }},
		{name: "suppressed count", mutate: func(record *evidence.Record) { record.Suppressed = 1 }},
		{name: "report digest", mutate: func(record *evidence.Record) { record.ReportSHA256 = testReport }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := input.Records[0]
			test.mutate(&record)
			findings := validateRecordAgainstExpected(input.Plan, input.Plan.Expected[0], record)
			assertFindingCodes(t, findings, "invalid-na-record")
		})
	}
}

func TestEvaluateObservationsContinuesAfterInvalidObservation(t *testing.T) {
	input := validInput(t)
	expected := input.Plan.Expected[0]
	record := input.Records[0]
	record.FindingCount = 2
	invalid := validObservation(false)
	invalid.Source = "unsupported"
	unmatched := validObservation(false)
	unmatched.Fingerprint = "sha256:unmatched-observation"

	findings := evaluateObservations(expected, record, []Observation{invalid, unmatched}, exceptions.Set{}, nil)
	assertFindingCodes(t, findings, "invalid-observation", "open-finding")
}

func TestEvaluateObservationsContinuesAfterUnmatchedObservation(t *testing.T) {
	input := validInput(t)
	record := input.Records[0]
	record.FindingCount = 2
	first := validObservation(false)
	second := validObservation(false)
	second.Fingerprint = "sha256:second-unmatched-observation"

	findings := evaluateObservations(input.Plan.Expected[0], record, []Observation{first, second}, exceptions.Set{}, nil)
	assertFindingCodes(t, findings, "open-finding", "open-finding")
}

func TestEvaluateObservationsContinuesAfterReusedException(t *testing.T) {
	input := validInput(t)
	record := input.Records[0]
	record.Outcome = evidence.OutcomeFail
	record.FindingCount = 3
	matched := validObservation(false)
	unmatched := validObservation(false)
	unmatched.Fingerprint = "sha256:unmatched-after-reuse"
	set := validExceptionSet(t, matched)
	consumed := make([]bool, len(set.Entries()))

	findings := evaluateObservations(input.Plan.Expected[0], record, []Observation{matched, matched, unmatched}, set, consumed)
	assertFindingCodes(t, findings, "exception-reused", "open-finding")
}

func TestValidateObservationRejectsEachInvalidScopeClass(t *testing.T) {
	expected := validInput(t).Plan.Expected[0]
	for _, scope := range []string{".", "../outside.go"} {
		t.Run(strings.ReplaceAll(scope, "/", "_"), func(t *testing.T) {
			observation := validObservation(false)
			observation.Scope = scope
			err := validateObservation(expected, observation)
			if err == nil || err.Error() != "scope must be an exact non-root repository path" {
				t.Fatalf("validateObservation(scope %q) error = %v", scope, err)
			}
		})
	}
}

func assertFindingCodes(t *testing.T, findings []Finding, want ...string) {
	t.Helper()
	got := make([]string, len(findings))
	for index, finding := range findings {
		got[index] = finding.Code
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("finding codes = %q, want %q; findings = %#v", got, want, findings)
	}
}
