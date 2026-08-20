package acceptance

import (
	"bytes"
	"strings"
	"testing"
)

func TestAcceptanceRecordCanonicalRoundTrip(t *testing.T) {
	record := validAcceptanceRecord()
	data, err := MarshalRecord(record)
	if err != nil {
		t.Fatalf("MarshalRecord() error = %v", err)
	}
	got, err := DecodeRecord(bytes.NewReader(data), testCandidateSHA)
	if err != nil {
		t.Fatalf("DecodeRecord() error = %v", err)
	}
	if mustJSON(t, got) != mustJSON(t, record) {
		t.Fatalf("DecodeRecord() = %#v, want %#v", got, record)
	}

	tests := []struct {
		name string
		data string
		sha  string
		want string
	}{
		{name: "empty", want: "empty"},
		{name: "unknown", data: strings.Replace(string(data), `"schema_version":"1"`, `"schema_version":"1","unknown":true`, 1), sha: testCandidateSHA, want: "unknown field"},
		{name: "trailing", data: string(data) + `{}`, sha: testCandidateSHA, want: "acceptance record contains a trailing JSON value"},
		{name: "malformed trailing", data: string(data) + `{`, sha: testCandidateSHA, want: "decode trailing acceptance record: unexpected EOF"},
		{name: "pretty", data: strings.ReplaceAll(string(data), `,"`, ",\n\t\""), sha: testCandidateSHA, want: "canonical"},
		{name: "wrong candidate", data: string(data), sha: strings.Repeat("d", 40), want: "does not match"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeRecord(strings.NewReader(test.data), test.sha)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("DecodeRecord() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateAcceptanceRecordRejectsBrokenBinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Record)
		want   string
	}{
		{name: "wrong order", mutate: func(record *Record) { record.Runs[0], record.Runs[1] = record.Runs[1], record.Runs[0] }, want: "kind"},
		{name: "duplicate run", mutate: func(record *Record) { record.Runs[1].ID = record.Runs[0].ID }, want: "duplicate"},
		{name: "fork repository", mutate: func(record *Record) { record.Runs[2].HeadRepository = testCanary }, want: "different repository"},
		{name: "consumer mismatch", mutate: func(record *Record) { record.Runs[1].HeadSHA = strings.Repeat("d", 40) }, want: "same consumer commit"},
		{name: "wrong workflow", mutate: func(record *Record) { record.Runs[0].WorkflowPath = ".github/workflows/other.yml" }, want: "scenario"},
		{name: "central repository is not a canary", mutate: func(record *Record) { record.CanaryRepository = "gomaja/github-ci" }, want: "different owner/repository"},
		{name: "zero run id", mutate: func(record *Record) { record.Runs[0].ID = 0 }, want: "id must be positive"},
		{name: "zero pull request", mutate: func(record *Record) { record.Runs[2].PullRequest = 0 }, want: "identify a pull request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validAcceptanceRecord()
			test.mutate(&record)
			if err := ValidateRecord(record, testCandidateSHA); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateRecord() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDecodeAcceptanceRecordEnforcesSizeLimit(t *testing.T) {
	_, err := DecodeRecord(strings.NewReader(strings.Repeat(" ", maxRecordSize+1)), testCandidateSHA)
	if err == nil || err.Error() != "acceptance record exceeds 1048576 byte limit" {
		t.Fatalf("DecodeRecord(oversized) error = %v", err)
	}
}

func validAcceptanceRecord() Record {
	return Record{
		SchemaVersion: SchemaVersion, CandidateSHA: testCandidateSHA, CanaryRepository: testCanary,
		Runs: []RunRecord{
			{Kind: RunStandard, ID: 101, Repository: testCanary, HeadRepository: testCanary, Event: "workflow_dispatch", HeadSHA: testConsumerSHA, WorkflowPath: ".github/workflows/github-ci.yml", WorkflowSHA: testCandidateSHA, GateJob: "gate / gate"},
			{Kind: RunDeep, ID: 102, Repository: testCanary, HeadRepository: testCanary, Event: "workflow_dispatch", HeadSHA: testConsumerSHA, WorkflowPath: ".github/workflows/github-ci-deep.yml", WorkflowSHA: testCandidateSHA, GateJob: "assurance / gate"},
			{Kind: RunFork, ID: 103, Repository: testCanary, HeadRepository: testFork, Event: "pull_request", HeadSHA: testForkSHA, WorkflowPath: ".github/workflows/github-ci.yml", WorkflowSHA: testCandidateSHA, GateJob: "gate / gate", PullRequest: 7},
		},
		ConfigSHA256: strings.Repeat("e", 64),
	}
}
