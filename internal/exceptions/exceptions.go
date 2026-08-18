// Package exceptions defines reviewed, expiring analyzer exceptions.
package exceptions

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/gomaja/github-ci/internal/applicability"
	"github.com/gomaja/github-ci/internal/pathpolicy"
	"gopkg.in/yaml.v3"
)

const (
	schemaVersion    = 1
	maxDocumentBytes = 1 << 20
	maxExceptionDays = 90
)

var (
	rulePattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
	fingerprintPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+/=-]{7,511}$`)
)

// Date is an exact UTC civil date.
type Date struct{ value time.Time }

// String renders the canonical YYYY-MM-DD representation.
func (date Date) String() string {
	if date.value.IsZero() {
		return ""
	}
	return date.value.Format(time.DateOnly)
}

// Entry is one reviewed exception to an exact analyzer observation.
type Entry struct {
	Tool              string
	Rule              string
	Fingerprint       string
	Scope             string
	Rationale         string
	Owner             string
	Approval          string
	Created           Date
	Expires           Date
	VerificationTests []string
}

// Identity returns the complete one-to-one matching identity.
func (entry Entry) Identity() string {
	return entry.Tool + "/" + entry.Rule + "/" + entry.Fingerprint + "/" + entry.Scope
}

// FingerprintIdentity identifies a finding independently of its claimed scope.
func (entry Entry) FingerprintIdentity() string {
	return entry.Tool + "/" + entry.Rule + "/" + entry.Fingerprint
}

// Set contains only loader-validated, unique exceptions.
type Set struct {
	entries     []Entry
	validatedOn Date
}

// Entries returns an independent copy of the validated exceptions.
func (set Set) Entries() []Entry {
	entries := slices.Clone(set.entries)
	for index := range entries {
		entries[index].VerificationTests = slices.Clone(entries[index].VerificationTests)
	}
	return entries
}

// ValidatedOn returns the UTC civil date used by the loader.
func (set Set) ValidatedOn() string { return set.validatedOn.String() }

// ValidateOn rechecks every lifecycle invariant on an explicit UTC civil date.
func (set Set) ValidateOn(date string) []Issue {
	currentDate, err := parseDate(date)
	if err != nil {
		return []Issue{{Index: -1, Code: "invalid-validation-date", Detail: err.Error()}}
	}
	_, issues := validateWires(set.wires(), currentDate)
	return issues
}

// FindExact returns the matching entry index, or -1 when no entry matches.
func (set Set) FindExact(tool, rule, fingerprint, scope string) int {
	return slices.IndexFunc(set.entries, func(entry Entry) bool {
		return entry.Tool == tool && entry.Rule == rule && entry.Fingerprint == fingerprint && entry.Scope == scope
	})
}

// Issue is one deterministic semantic problem in an exception document.
type Issue struct {
	Index  int
	Code   string
	Detail string
}

type documentWire struct {
	SchemaVersion int         `yaml:"schema-version"`
	Exceptions    []entryWire `yaml:"exceptions"`
}

type entryWire struct {
	Tool              string   `json:"tool" yaml:"tool"`
	Rule              string   `json:"rule" yaml:"rule"`
	Fingerprint       string   `json:"fingerprint" yaml:"fingerprint"`
	Scope             string   `json:"scope" yaml:"scope"`
	Rationale         string   `json:"rationale" yaml:"rationale"`
	Owner             string   `json:"owner" yaml:"owner"`
	Approval          string   `json:"approval" yaml:"approval"`
	Created           string   `json:"created" yaml:"created"`
	Expires           string   `json:"expires" yaml:"expires"`
	VerificationTests []string `json:"verification_tests,omitempty" yaml:"verification-tests,omitempty"`
}

type indexedEntry struct {
	index int
	entry Entry
}

type setJSON struct {
	SchemaVersion int         `json:"schema_version"`
	ValidatedOn   string      `json:"validated_on,omitempty"`
	Entries       []entryWire `json:"entries"`
}

// LoadDetailed decodes one strict document and separates syntax from semantic issues.
func LoadDetailed(reader io.Reader, now time.Time) (Set, []Issue, error) {
	if reader == nil {
		return Set{}, nil, errors.New("exception reader is nil")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxDocumentBytes+1))
	if err != nil {
		return Set{}, nil, fmt.Errorf("read exceptions: %w", err)
	}
	if len(data) > maxDocumentBytes {
		return Set{}, nil, fmt.Errorf("exception document exceeds %d bytes", maxDocumentBytes)
	}

	var node yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&node); err != nil {
		if errors.Is(err, io.EOF) {
			return Set{}, nil, errors.New("empty exception document")
		}
		return Set{}, nil, fmt.Errorf("decode exceptions: %w", err)
	}
	if node.Kind == 0 || len(node.Content) == 0 {
		return Set{}, nil, errors.New("empty exception document")
	}
	if err := rejectDuplicateKeys(&node); err != nil {
		return Set{}, nil, err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Set{}, nil, errors.New("exception document contains multiple YAML documents")
		}
		return Set{}, nil, fmt.Errorf("decode trailing exception document: %w", err)
	}

	encoded, err := yaml.Marshal(&node)
	if err != nil {
		return Set{}, nil, fmt.Errorf("encode exception node: %w", err)
	}
	var document documentWire
	strict := yaml.NewDecoder(bytes.NewReader(encoded))
	strict.KnownFields(true)
	if err := strict.Decode(&document); err != nil {
		return Set{}, nil, fmt.Errorf("decode strict exceptions: %w", err)
	}

	issues := make([]Issue, 0)
	if document.SchemaVersion != schemaVersion {
		issues = append(issues, Issue{Index: -1, Code: "invalid-schema-version", Detail: fmt.Sprintf("schema-version must be %d", schemaVersion)})
	}
	currentDate := civilDate(now)
	set, entryIssues := validateWires(document.Exceptions, currentDate)
	issues = append(issues, entryIssues...)
	sortIssues(issues)
	return set, issues, nil
}

// MarshalJSON preserves validated exception entries without exposing mutable state.
func (set Set) MarshalJSON() ([]byte, error) {
	wires := set.wires()
	if len(wires) != 0 && set.validatedOn.String() == "" {
		return nil, errors.New("exception set has entries without a validation date")
	}
	return json.Marshal(setJSON{SchemaVersion: schemaVersion, ValidatedOn: set.validatedOn.String(), Entries: wires})
}

// UnmarshalJSON strictly reconstructs a semantically validated exception set.
func (set *Set) UnmarshalJSON(data []byte) error {
	if set == nil {
		return errors.New("exception set destination is nil")
	}
	if len(data) > maxDocumentBytes {
		return fmt.Errorf("exception JSON exceeds %d bytes", maxDocumentBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	if err := validateSetJSONShape(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire setJSON
	if err := decoder.Decode(&wire); err != nil {
		return fmt.Errorf("decode exception JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	if wire.SchemaVersion != schemaVersion {
		return fmt.Errorf("exception JSON schema_version must be %d", schemaVersion)
	}
	if len(wire.Entries) == 0 && wire.ValidatedOn == "" {
		*set = Set{}
		return nil
	}
	validatedOn, err := parseDate(wire.ValidatedOn)
	if err != nil {
		return fmt.Errorf("invalid exception JSON validated_on: %w", err)
	}
	validated, issues := validateWires(wire.Entries, validatedOn)
	if len(issues) != 0 {
		return fmt.Errorf("invalid exception JSON entry %d: %s: %s", issues[0].Index, issues[0].Code, issues[0].Detail)
	}
	*set = validated
	return nil
}

func validateWires(wires []entryWire, currentDate time.Time) (Set, []Issue) {
	issues := make([]Issue, 0)
	candidates := make([]indexedEntry, 0, len(wires))
	for index, wire := range wires {
		entry, entryIssues := validateEntry(index, wire, currentDate)
		issues = append(issues, entryIssues...)
		if len(entryIssues) == 0 {
			candidates = append(candidates, indexedEntry{index: index, entry: entry})
		}
	}

	counts := make(map[string]int, len(candidates))
	fingerprintCounts := make(map[string]int, len(candidates))
	for _, candidate := range candidates {
		counts[candidate.entry.Identity()]++
		fingerprintCounts[candidate.entry.FingerprintIdentity()]++
	}
	entries := make([]Entry, 0, len(candidates))
	for _, candidate := range candidates {
		if counts[candidate.entry.Identity()] > 1 {
			issues = append(issues, Issue{Index: candidate.index, Code: "duplicate-exception", Detail: candidate.entry.Identity()})
			continue
		}
		if fingerprintCounts[candidate.entry.FingerprintIdentity()] > 1 {
			issues = append(issues, Issue{Index: candidate.index, Code: "duplicate-fingerprint", Detail: candidate.entry.FingerprintIdentity()})
			continue
		}
		entries = append(entries, candidate.entry)
	}
	slices.SortFunc(entries, func(left, right Entry) int { return strings.Compare(left.Identity(), right.Identity()) })
	sortIssues(issues)
	return Set{entries: entries, validatedOn: Date{value: currentDate}}, issues
}

func (set Set) wires() []entryWire {
	wires := make([]entryWire, 0, len(set.entries))
	for _, entry := range set.entries {
		wires = append(wires, entryWire{
			Tool: entry.Tool, Rule: entry.Rule, Fingerprint: entry.Fingerprint,
			Scope: entry.Scope, Rationale: entry.Rationale, Owner: entry.Owner,
			Approval: entry.Approval, Created: entry.Created.String(), Expires: entry.Expires.String(),
			VerificationTests: slices.Clone(entry.VerificationTests),
		})
	}
	return wires
}

// Load rejects both fatal syntax errors and semantic issues.
func Load(reader io.Reader, now time.Time) (Set, error) {
	set, issues, err := LoadDetailed(reader, now)
	if err != nil {
		return Set{}, err
	}
	if len(issues) != 0 {
		return Set{}, fmt.Errorf("exception issue %s: %s (%d total)", issues[0].Code, issues[0].Detail, len(issues))
	}
	return set, nil
}

func validateEntry(index int, wire entryWire, today time.Time) (Entry, []Issue) {
	entry := Entry{
		Tool: wire.Tool, Rule: wire.Rule, Fingerprint: wire.Fingerprint,
		Scope: wire.Scope, Rationale: wire.Rationale, Owner: wire.Owner,
		Approval: wire.Approval, VerificationTests: slices.Clone(wire.VerificationTests),
	}
	var issues []Issue
	add := func(code, detail string) { issues = append(issues, Issue{Index: index, Code: code, Detail: detail}) }

	if err := validateText("tool", wire.Tool); err != nil {
		add("invalid-tool", err.Error())
	} else if !applicability.IsKnownTool(wire.Tool) {
		add("unknown-tool", wire.Tool)
	}
	if err := validateText("rule", wire.Rule); err != nil || !rulePattern.MatchString(wire.Rule) {
		add("invalid-rule", "rule must be an exact analyzer identifier")
	}
	if err := validateText("fingerprint", wire.Fingerprint); err != nil || !fingerprintPattern.MatchString(wire.Fingerprint) || isPlaceholder(wire.Fingerprint) {
		add("invalid-fingerprint", "fingerprint must be a stable exact identifier")
	}
	if strings.ContainsAny(wire.Scope, "*?[]{}") {
		add("wildcard-scope", wire.Scope)
	} else if err := pathpolicy.Validate("scope", wire.Scope); err != nil {
		add("invalid-scope", err.Error())
	} else if wire.Scope == "." {
		add("overbroad-scope", "repository-root scope is not permitted")
	}
	if err := validateText("rationale", wire.Rationale); err != nil || len(strings.TrimSpace(wire.Rationale)) < 20 || isPlaceholder(wire.Rationale) {
		add("invalid-rationale", "rationale must contain a technical false-positive or equivalent-mutant explanation")
	}
	if err := validateText("owner", wire.Owner); err != nil || isPlaceholder(wire.Owner) {
		add("invalid-owner", "owner must identify the accountable maintainer")
	}
	if err := validateText("approval", wire.Approval); err != nil || isPlaceholder(wire.Approval) || (!strings.Contains(wire.Approval, "#") && !strings.HasPrefix(wire.Approval, "https://")) {
		add("invalid-approval", "approval must be a durable issue, pull request, or HTTPS reference")
	}

	created, err := parseDate(wire.Created)
	if err != nil {
		add("invalid-created", err.Error())
	} else {
		entry.Created = Date{value: created}
		if created.After(today) {
			add("future-created", wire.Created)
		}
	}
	expires, err := parseDate(wire.Expires)
	if err != nil {
		add("invalid-expires", err.Error())
	} else {
		entry.Expires = Date{value: expires}
		if expires.Before(created) && !created.IsZero() {
			add("expiry-before-creation", wire.Expires)
		}
		if expires.Sub(created) > maxExceptionDays*24*time.Hour && !created.IsZero() {
			add("expiry-too-distant", fmt.Sprintf("exception duration exceeds %d days", maxExceptionDays))
		}
		if today.After(expires) {
			add("expired", wire.Expires)
		}
	}
	for _, verificationTest := range wire.VerificationTests {
		if err := pathpolicy.Validate("verification test", verificationTest); err != nil {
			add("invalid-verification-test", err.Error())
		}
	}
	sortIssues(issues)
	return entry, issues
}

func rejectDuplicateKeys(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index].Value
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate YAML key %q", key)
			}
			seen[key] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := rejectDuplicateKeys(child); err != nil {
			return err
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(decoder, 0); err != nil {
		return fmt.Errorf("validate exception JSON: %w", err)
	}
	return requireJSONEOF(decoder)
}

func validateSetJSONShape(data []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("decode exception JSON shape: %w", err)
	}
	allowedRoot := map[string]struct{}{"schema_version": {}, "validated_on": {}, "entries": {}}
	for key := range root {
		if _, allowed := allowedRoot[key]; !allowed {
			return fmt.Errorf("unknown exception JSON field %q", key)
		}
	}
	entriesJSON, exists := root["entries"]
	if !exists {
		return errors.New("exception JSON entries field is required")
	}
	trimmed := bytes.TrimSpace(entriesJSON)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return errors.New("exception JSON entries must be an array")
	}
	if validatedJSON, present := root["validated_on"]; present {
		var validatedOn string
		if len(bytes.TrimSpace(validatedJSON)) == 0 || bytes.TrimSpace(validatedJSON)[0] != '"' || json.Unmarshal(validatedJSON, &validatedOn) != nil || validatedOn == "" {
			return errors.New("exception JSON validated_on must be a non-empty date string when present")
		}
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(entriesJSON, &entries); err != nil {
		return fmt.Errorf("decode exception JSON entries: %w", err)
	}
	allowedEntry := map[string]struct{}{
		"tool": {}, "rule": {}, "fingerprint": {}, "scope": {}, "rationale": {},
		"owner": {}, "approval": {}, "created": {}, "expires": {}, "verification_tests": {},
	}
	for index, entry := range entries {
		for key := range entry {
			if _, allowed := allowedEntry[key]; !allowed {
				return fmt.Errorf("unknown exception JSON entries[%d] field %q", index, key)
			}
		}
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 256 {
		return errors.New("JSON nesting exceeds 256 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			foldedKey := strings.ToLower(key)
			if _, exists := seen[foldedKey]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[foldedKey] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("exception JSON contains trailing data")
	}
	return fmt.Errorf("decode trailing exception JSON: %w", err)
}

func parseDate(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("date must not be empty")
	}
	date, err := time.Parse(time.DateOnly, value)
	if err != nil || date.Format(time.DateOnly) != value {
		return time.Time{}, fmt.Errorf("date %q must use YYYY-MM-DD", value)
	}
	return date, nil
}

func civilDate(value time.Time) time.Time {
	year, month, day := value.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

func validateText(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}

func isPlaceholder(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "n/a", "na", "none", "unknown", "placeholder", "todo", "temporary", "false positive", "approved", "owner":
		return true
	default:
		return false
	}
}

func sortIssues(issues []Issue) {
	slices.SortFunc(issues, func(left, right Issue) int {
		if left.Index != right.Index {
			return left.Index - right.Index
		}
		if comparison := strings.Compare(left.Code, right.Code); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Detail, right.Detail)
	})
}
