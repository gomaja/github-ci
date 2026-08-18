package evidence

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

const (
	testSubjectSHA = "0123456789abcdef0123456789abcdef01234567"
	testReportSHA  = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testPolicySHA  = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)

func TestValidateRecordAcceptsValidOutcomes(t *testing.T) {
	tests := []struct {
		name   string
		record Record
	}{
		{name: "pass", record: validRecord()},
		{name: "finding", record: findingRecord()},
		{name: "not applicable", record: notApplicableRecord()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateRecord(test.record); err != nil {
				t.Fatalf("ValidateRecord() error = %v", err)
			}
		})
	}
}

func TestValidateRecordRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Record)
		want   string
	}{
		{name: "schema", mutate: func(record *Record) { record.SchemaVersion = "2" }, want: "schema_version"},
		{name: "applicability", mutate: func(record *Record) { record.Applicability = "sometimes" }, want: "applicability"},
		{name: "outcome", mutate: func(record *Record) { record.Outcome = "warning" }, want: "outcome"},
		{name: "negative finding count", mutate: func(record *Record) { record.FindingCount = -1 }, want: "finding_count"},
		{name: "negative suppressed count", mutate: func(record *Record) { record.Suppressed = -1 }, want: "suppressed_count"},
		{name: "pass with findings", mutate: func(record *Record) { record.FindingCount = 1 }, want: "passing record"},
		{name: "missing report hash", mutate: func(record *Record) { record.ReportSHA256 = "" }, want: "report_sha256"},
		{name: "absolute command path", mutate: func(record *Record) { record.CommandID = "/tmp/report" }, want: "relative"},
		{name: "traversing command path", mutate: func(record *Record) { record.CommandID = "lint/../report" }, want: "traversal"},
		{name: "n/a finding", mutate: func(record *Record) { *record = notApplicableRecord(); record.FindingCount = 1 }, want: "N/A record"},
		{name: "n/a report", mutate: func(record *Record) { *record = notApplicableRecord(); record.ReportSHA256 = testReportSHA }, want: "N/A record"},
		{name: "n/a applicable", mutate: func(record *Record) { record.Outcome = OutcomeNotApplicable }, want: "applicable record"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validRecord()
			test.mutate(&record)
			err := ValidateRecord(record)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateRecord() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateRecordsRejectsMismatchedSubjectSHA(t *testing.T) {
	err := ValidateRecords(testSubjectSHA, []Record{{
		SchemaVersion: SchemaVersion,
		Tool:          "staticcheck",
		ToolVersion:   "2026.1",
		PolicyVersion: testPolicySHA,
		SubjectSHA:    "abcdef0123456789abcdef0123456789abcdef01",
		Applicability: Applicable,
		CommandID:     "staticcheck/default",
		ExitCode:      0,
		FindingCount:  0,
		Suppressed:    0,
		ReportSHA256:  testReportSHA,
		Outcome:       OutcomePass,
	}})
	if err == nil || !strings.Contains(err.Error(), "subject_sha") {
		t.Fatalf("ValidateRecords() error = %v, want subject_sha mismatch", err)
	}
}

func TestValidateRecordsRejectsDuplicateIdentity(t *testing.T) {
	record := validRecord()
	err := ValidateRecords(testSubjectSHA, []Record{record, record})
	if err == nil || !strings.Contains(err.Error(), "duplicate evidence identity") {
		t.Fatalf("ValidateRecords() error = %v, want duplicate identity", err)
	}
}

func TestRecordIdentity(t *testing.T) {
	if got := validRecord().Identity(); got != "staticcheck/staticcheck/default" {
		t.Fatalf("Identity() = %q", got)
	}
}

func TestValidatePlanAcceptsCanonicalPlan(t *testing.T) {
	plan := validPlan()
	if err := ValidatePlan(plan); err != nil {
		t.Fatalf("ValidatePlan() error = %v", err)
	}
}

func TestValidatePlanRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Plan)
		want   string
	}{
		{name: "schema", mutate: func(plan *Plan) { plan.SchemaVersion = "2" }, want: "schema_version"},
		{name: "detector", mutate: func(plan *Plan) { plan.DetectorVersion = "" }, want: "detector_version"},
		{name: "subject", mutate: func(plan *Plan) { plan.SubjectSHA = strings.ToUpper(plan.SubjectSHA) }, want: "subject_sha"},
		{name: "tree", mutate: func(plan *Plan) { plan.TreeSHA256 = "sha256:short" }, want: "tree_sha256"},
		{name: "policy", mutate: func(plan *Plan) { plan.PolicySHA256 = "sha256:short" }, want: "policy_sha256"},
		{name: "empty expected", mutate: func(plan *Plan) { plan.Expected = nil }, want: "expected"},
		{name: "tool", mutate: func(plan *Plan) { plan.Expected[0].Tool = "StaticCheck" }, want: "tool"},
		{name: "command", mutate: func(plan *Plan) { plan.Expected[0].CommandID = "../outside" }, want: "command_id"},
		{name: "parser", mutate: func(plan *Plan) { plan.Expected[0].ParserVersion = "" }, want: "parser_version"},
		{name: "applicability", mutate: func(plan *Plan) { plan.Expected[0].Applicability = "sometimes" }, want: "applicability"},
		{name: "applicable reason", mutate: func(plan *Plan) { plan.Expected[0].ReasonCode = "no-go-module" }, want: "reason_code"},
		{name: "missing n/a reason", mutate: func(plan *Plan) { plan.Expected[1].ReasonCode = "" }, want: "reason_code"},
		{name: "invalid n/a reason", mutate: func(plan *Plan) { plan.Expected[1].ReasonCode = "No Dockerfile" }, want: "reason_code"},
		{name: "duplicate", mutate: func(plan *Plan) { plan.Expected[1] = plan.Expected[0] }, want: "duplicate expected identity"},
		{name: "unsorted", mutate: func(plan *Plan) { plan.Expected[0], plan.Expected[1] = plan.Expected[1], plan.Expected[0] }, want: "sorted"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := validPlan()
			test.mutate(&plan)
			err := ValidatePlan(plan)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidatePlan() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestPlanDigestIsCanonicalAndContentBound(t *testing.T) {
	plan := validPlan()
	first, err := plan.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	second, err := plan.Digest()
	if err != nil {
		t.Fatalf("second Digest() error = %v", err)
	}
	if first != second {
		t.Fatalf("Digest() = %q then %q", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Fatalf("Digest() = %q, want lowercase SHA-256 digest", first)
	}

	mutated := validPlan()
	mutated.Expected[0].ParserVersion = "staticcheck-jsonl/v2"
	changed, err := mutated.Digest()
	if err != nil {
		t.Fatalf("mutated Digest() error = %v", err)
	}
	if changed == first {
		t.Fatal("Digest() did not bind parser_version")
	}
}

func TestExpectedIdentity(t *testing.T) {
	if got := validPlan().Expected[0].Identity(); got != "hadolint/hadolint/dockerfiles" {
		t.Fatalf("Identity() = %q", got)
	}
}

func FuzzValidatePlan(f *testing.F) {
	valid, err := json.Marshal(validPlan())
	if err != nil {
		f.Fatalf("marshal seed: %v", err)
	}
	f.Add(valid)
	f.Add([]byte(`{"schema_version":"1","expected":[]}`))
	f.Add([]byte(`{"schema_version":`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		var plan Plan
		if err := json.Unmarshal(data, &plan); err != nil {
			return
		}
		_ = ValidatePlan(plan)
		_, _ = plan.Digest()
	})
}

func TestEvidenceSchemaIsStrictJSONSchema(t *testing.T) {
	data, err := os.ReadFile("../../schemas/evidence.schema.json")
	if err != nil {
		t.Fatalf("read evidence schema: %v", err)
	}
	var schema struct {
		Schema               string         `json:"$schema"`
		AdditionalProperties bool           `json:"additionalProperties"`
		Required             []string       `json:"required"`
		Properties           map[string]any `json:"properties"`
		AllOf                []any          `json:"allOf"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("unmarshal evidence schema: %v", err)
	}
	if schema.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema = %q", schema.Schema)
	}
	if schema.AdditionalProperties {
		t.Fatal("additionalProperties = true")
	}
	if len(schema.Required) != 11 || len(schema.Properties) != 12 || len(schema.AllOf) == 0 {
		t.Fatalf("required/properties/conditional rules = %d/%d/%d, want 11/12/non-zero", len(schema.Required), len(schema.Properties), len(schema.AllOf))
	}
}

func validRecord() Record {
	return Record{
		SchemaVersion: SchemaVersion,
		Tool:          "staticcheck",
		ToolVersion:   "2026.1",
		PolicyVersion: testPolicySHA,
		SubjectSHA:    testSubjectSHA,
		Applicability: Applicable,
		CommandID:     "staticcheck/default",
		ExitCode:      0,
		FindingCount:  0,
		Suppressed:    0,
		ReportSHA256:  testReportSHA,
		Outcome:       OutcomePass,
	}
}

func findingRecord() Record {
	record := validRecord()
	record.ExitCode = 1
	record.FindingCount = 1
	record.Outcome = OutcomeFail
	return record
}

func notApplicableRecord() Record {
	record := validRecord()
	record.Applicability = NotApplicable
	record.CommandID = "staticcheck/not-applicable"
	record.ReportSHA256 = ""
	record.Outcome = OutcomeNotApplicable
	return record
}

func validPlan() Plan {
	expected := []Expected{
		{
			Tool:          "hadolint",
			CommandID:     "hadolint/dockerfiles",
			ParserVersion: "sarif/v1",
			Applicability: Applicable,
		},
		{
			Tool:          "shellcheck",
			CommandID:     "shellcheck/scripts",
			ParserVersion: "shellcheck-json1/v1",
			Applicability: NotApplicable,
			ReasonCode:    "no-shell-files",
		},
	}
	slices.SortFunc(expected, func(left, right Expected) int {
		return strings.Compare(left.Identity(), right.Identity())
	})
	return Plan{
		SchemaVersion:   SchemaVersion,
		DetectorVersion: "applicability/v1",
		SubjectSHA:      testSubjectSHA,
		TreeSHA256:      testReportSHA,
		PolicySHA256:    testPolicySHA,
		Expected:        expected,
	}
}
