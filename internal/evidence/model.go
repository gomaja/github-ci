// Package evidence defines normalized assurance evidence and its invariants.
package evidence

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
)

const SchemaVersion = "1"

var (
	gitSHAPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	toolNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	windowsAbsPattern = regexp.MustCompile(`^[A-Za-z]:[/\\]`)
)

// Applicability records whether policy requires a tool for the subject.
type Applicability string

const (
	Applicable    Applicability = "applicable"
	NotApplicable Applicability = "not-applicable"
)

// Outcome is the normalized result of an expected analyzer invocation.
type Outcome string

const (
	OutcomePass          Outcome = "pass"
	OutcomeFail          Outcome = "fail"
	OutcomeNotApplicable Outcome = "N/A"
)

// Record is one normalized analyzer result.
type Record struct {
	SchemaVersion string        `json:"schema_version"`
	Tool          string        `json:"tool"`
	ToolVersion   string        `json:"tool_version"`
	PolicyVersion string        `json:"policy_version"`
	SubjectSHA    string        `json:"subject_sha"`
	Applicability Applicability `json:"applicability"`
	CommandID     string        `json:"command_id"`
	ExitCode      int           `json:"exit_code"`
	FindingCount  int           `json:"finding_count"`
	Suppressed    int           `json:"suppressed_count"`
	ReportSHA256  string        `json:"report_sha256,omitempty"`
	Outcome       Outcome       `json:"outcome"`
}

// Expected describes one record required by an applicability plan.
type Expected struct {
	Tool          string        `json:"tool"`
	CommandID     string        `json:"command_id"`
	Applicability Applicability `json:"applicability"`
	ReasonCode    string        `json:"reason_code,omitempty"`
}

// Plan binds expected evidence to detector and source-tree identities.
type Plan struct {
	SchemaVersion   string     `json:"schema_version"`
	DetectorVersion string     `json:"detector_version"`
	SubjectSHA      string     `json:"subject_sha"`
	TreeSHA256      string     `json:"tree_sha256"`
	Expected        []Expected `json:"expected"`
}

// Identity returns the stable tool/command_id record identity.
func (record Record) Identity() string {
	return record.Tool + "/" + record.CommandID
}

// MarshalJSON emits fields in Record declaration order.
func (record Record) MarshalJSON() ([]byte, error) {
	type plainRecord Record
	return json.Marshal(plainRecord(record))
}

// ValidateRecord verifies the standalone evidence contract.
func ValidateRecord(record Record) error {
	if record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %q", SchemaVersion)
	}
	if !toolNamePattern.MatchString(record.Tool) {
		return fmt.Errorf("tool must be a lowercase identifier: %q", record.Tool)
	}
	if err := validateText("tool_version", record.ToolVersion); err != nil {
		return err
	}
	if !sha256Pattern.MatchString(record.PolicyVersion) {
		return fmt.Errorf("policy_version must be a lowercase SHA-256 digest")
	}
	if !gitSHAPattern.MatchString(record.SubjectSHA) {
		return fmt.Errorf("subject_sha must be a 40-character lowercase hexadecimal commit SHA")
	}
	if record.Applicability != Applicable && record.Applicability != NotApplicable {
		return fmt.Errorf("unsupported applicability %q", record.Applicability)
	}
	if err := validateRelativePath("command_id", record.CommandID); err != nil {
		return err
	}
	if record.ExitCode < 0 {
		return fmt.Errorf("exit_code must not be negative")
	}
	if record.FindingCount < 0 {
		return fmt.Errorf("finding_count must not be negative")
	}
	if record.Suppressed < 0 {
		return fmt.Errorf("suppressed_count must not be negative")
	}
	if record.Outcome != OutcomePass && record.Outcome != OutcomeFail && record.Outcome != OutcomeNotApplicable {
		return fmt.Errorf("unsupported outcome %q", record.Outcome)
	}

	if record.Applicability == NotApplicable {
		if record.Outcome != OutcomeNotApplicable || record.ExitCode != 0 || record.FindingCount != 0 || record.Suppressed != 0 || record.ReportSHA256 != "" {
			return fmt.Errorf("N/A record must have outcome N/A, zero counts and exit code, and no report_sha256")
		}
		return nil
	}
	if record.Outcome == OutcomeNotApplicable {
		return fmt.Errorf("applicable record must not have outcome N/A")
	}
	if !sha256Pattern.MatchString(record.ReportSHA256) {
		return fmt.Errorf("report_sha256 must be a lowercase SHA-256 digest for applicable evidence")
	}
	if record.Outcome == OutcomePass && (record.ExitCode != 0 || record.FindingCount != 0) {
		return fmt.Errorf("passing record must have zero exit_code and finding_count")
	}
	return nil
}

// ValidateRecords validates records against a subject and rejects duplicate identities.
func ValidateRecords(subjectSHA string, records []Record) error {
	if !gitSHAPattern.MatchString(subjectSHA) {
		return fmt.Errorf("expected subject_sha must be a 40-character lowercase hexadecimal commit SHA")
	}
	identities := make(map[string]struct{}, len(records))
	for index, record := range records {
		if err := ValidateRecord(record); err != nil {
			return fmt.Errorf("record %d: %w", index, err)
		}
		if record.SubjectSHA != subjectSHA {
			return fmt.Errorf("record %d subject_sha %q does not match %q", index, record.SubjectSHA, subjectSHA)
		}
		identity := record.Identity()
		if _, exists := identities[identity]; exists {
			return fmt.Errorf("duplicate evidence identity %q", identity)
		}
		identities[identity] = struct{}{}
	}
	return nil
}

func validateRelativePath(field, value string) error {
	if err := validateText(field, value); err != nil {
		return err
	}
	if path.IsAbs(value) || strings.HasPrefix(value, `\`) || windowsAbsPattern.MatchString(value) {
		return fmt.Errorf("%s must be relative: %q", field, value)
	}
	if strings.Contains(value, `\`) {
		return fmt.Errorf("%s must use slash-separated paths: %q", field, value)
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return fmt.Errorf("%s must not contain traversal: %q", field, value)
		}
	}
	return nil
}

func validateText(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}
