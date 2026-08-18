package evidence

import (
	"encoding/json"
	"os"
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
