// Package acceptance verifies and records exact-commit release acceptance runs.
package acceptance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const (
	// SchemaVersion is the release acceptance evidence contract version.
	SchemaVersion       = "1"
	maxRecordSize       = 1 << 20
	standardCallerPath  = ".github/workflows/github-ci.yml"
	scheduledCallerPath = ".github/workflows/github-ci-deep.yml"
	standardGateName    = "gate / gate"
	manualDispatchEvent = "workflow_dispatch"
	contentTypeFile     = "file"
)

var (
	gitSHAPattern      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	repositoryPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	expectedRunOrder   = []RunKind{RunStandard, RunDeep, RunFork}
	expectedRunDetails = map[RunKind]struct {
		event, path, gate string
	}{
		RunStandard: {event: manualDispatchEvent, path: standardCallerPath, gate: standardGateName},
		RunDeep:     {event: manualDispatchEvent, path: scheduledCallerPath, gate: "assurance / gate"},
		RunFork:     {event: "pull_request", path: standardCallerPath, gate: standardGateName},
	}
)

// RunKind identifies one required acceptance scenario.
type RunKind string

const (
	// RunStandard is the external standard workflow canary.
	RunStandard RunKind = "standard"
	// RunDeep is the external deep workflow canary.
	RunDeep RunKind = "deep"
	// RunFork is the untrusted-fork standard workflow canary.
	RunFork RunKind = "fork"
)

// RunRecord binds a successful external run to its caller and release commit.
type RunRecord struct {
	Kind           RunKind `json:"kind"`
	ID             int64   `json:"id"`
	Repository     string  `json:"repository"`
	HeadRepository string  `json:"head_repository"`
	Event          string  `json:"event"`
	HeadSHA        string  `json:"head_sha"`
	WorkflowPath   string  `json:"workflow_path"`
	WorkflowSHA    string  `json:"workflow_sha"`
	GateJob        string  `json:"gate_job"`
	PullRequest    int64   `json:"pull_request,omitempty"`
}

// Record is canonical evidence that every release acceptance scenario passed.
type Record struct {
	SchemaVersion    string      `json:"schema_version"`
	CandidateSHA     string      `json:"candidate_sha"`
	CanaryRepository string      `json:"canary_repository"`
	Runs             []RunRecord `json:"runs"`
	ConfigSHA256     string      `json:"config_sha256"`
}

// ValidateRecord verifies the standalone and expected-commit record invariants.
func ValidateRecord(record Record, expectedSHA string) error {
	if err := validateRecordHeader(record, expectedSHA); err != nil {
		return err
	}
	ids := make(map[int64]struct{}, len(record.Runs))
	for index, run := range record.Runs {
		if err := validateRunRecord(record, run, index, ids, expectedSHA); err != nil {
			return err
		}
	}
	if record.Runs[0].HeadSHA != record.Runs[1].HeadSHA {
		return errors.New("standard and deep runs must use the same consumer commit")
	}
	return nil
}

func validateRecordHeader(record Record, expectedSHA string) error {
	if record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %q", SchemaVersion)
	}
	if !gitSHAPattern.MatchString(expectedSHA) {
		return errors.New("expected SHA must be a 40-character lowercase hexadecimal commit SHA")
	}
	if record.CandidateSHA != expectedSHA {
		return fmt.Errorf("candidate_sha %q does not match expected SHA %q", record.CandidateSHA, expectedSHA)
	}
	if !repositoryPattern.MatchString(record.CanaryRepository) || record.CanaryRepository == "gomaja/github-ci" {
		return errors.New("canary_repository must identify a different owner/repository")
	}
	if !sha256Pattern.MatchString(record.ConfigSHA256) {
		return errors.New("config_sha256 must be a lowercase SHA-256 digest")
	}
	if len(record.Runs) != len(expectedRunOrder) {
		return fmt.Errorf("runs must contain exactly %d acceptance records", len(expectedRunOrder))
	}
	return nil
}

func validateRunRecord(record Record, run RunRecord, index int, ids map[int64]struct{}, expectedSHA string) error {
	if run.Kind != expectedRunOrder[index] {
		return fmt.Errorf("run %d kind must be %q", index, expectedRunOrder[index])
	}
	details := expectedRunDetails[run.Kind]
	if run.ID <= 0 {
		return fmt.Errorf("run %q id must be positive", run.Kind)
	}
	if _, exists := ids[run.ID]; exists {
		return fmt.Errorf("duplicate run id %d", run.ID)
	}
	ids[run.ID] = struct{}{}
	if run.Repository != record.CanaryRepository {
		return fmt.Errorf("run %q repository does not match canary_repository", run.Kind)
	}
	if !repositoryPattern.MatchString(run.HeadRepository) {
		return fmt.Errorf("run %q head_repository is invalid", run.Kind)
	}
	if run.Event != details.event || run.WorkflowPath != details.path || run.GateJob != details.gate {
		return fmt.Errorf("run %q does not match its acceptance scenario", run.Kind)
	}
	if !gitSHAPattern.MatchString(run.HeadSHA) {
		return fmt.Errorf("run %q head_sha must be a 40-character lowercase hexadecimal commit SHA", run.Kind)
	}
	if run.WorkflowSHA != expectedSHA {
		return fmt.Errorf("run %q workflow_sha does not match the expected candidate SHA", run.Kind)
	}
	if run.Kind == RunFork {
		return validateForkRunRecord(record, run)
	}
	if run.HeadRepository != record.CanaryRepository {
		return fmt.Errorf("run %q must execute from the canary repository", run.Kind)
	}
	if run.PullRequest != 0 {
		return fmt.Errorf("run %q must not identify a pull request", run.Kind)
	}
	return nil
}

func validateForkRunRecord(record Record, run RunRecord) error {
	if run.HeadRepository == record.CanaryRepository {
		return errors.New("fork run head_repository must be a different repository")
	}
	if run.PullRequest <= 0 {
		return errors.New("fork run must identify a pull request")
	}
	return nil
}

// MarshalRecord emits a validated canonical record with one trailing newline.
func MarshalRecord(record Record) ([]byte, error) {
	if err := ValidateRecord(record, record.CandidateSHA); err != nil {
		return nil, err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal acceptance record: %w", err)
	}
	return append(data, '\n'), nil
}

// DecodeRecord decodes one bounded, strict, canonical acceptance record.
func DecodeRecord(reader io.Reader, expectedSHA string) (Record, error) {
	if reader == nil {
		return Record{}, errors.New("acceptance record reader is nil")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxRecordSize+1))
	if err != nil {
		return Record{}, fmt.Errorf("read acceptance record: %w", err)
	}
	if len(data) == 0 {
		return Record{}, errors.New("empty acceptance record")
	}
	if len(data) > maxRecordSize {
		return Record{}, fmt.Errorf("acceptance record exceeds %d byte limit", maxRecordSize)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fmt.Errorf("decode acceptance record: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Record{}, errors.New("acceptance record contains a trailing JSON value")
		}
		return Record{}, fmt.Errorf("decode trailing acceptance record: %w", err)
	}
	if err := ValidateRecord(record, expectedSHA); err != nil {
		return Record{}, fmt.Errorf("validate acceptance record: %w", err)
	}
	canonical, err := MarshalRecord(record)
	if err != nil {
		return Record{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Record{}, errors.New("acceptance record is not canonical JSON")
	}
	return record, nil
}
