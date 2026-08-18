// Package exceptions defines reviewed, expiring analyzer exceptions.
package exceptions

import (
	"bytes"
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

// Set contains only semantically valid, unique exceptions.
type Set struct{ Entries []Entry }

// FindExact returns the matching entry index, or -1 when no entry matches.
func (set Set) FindExact(tool, rule, fingerprint, scope string) int {
	return slices.IndexFunc(set.Entries, func(entry Entry) bool {
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
	Tool              string   `yaml:"tool"`
	Rule              string   `yaml:"rule"`
	Fingerprint       string   `yaml:"fingerprint"`
	Scope             string   `yaml:"scope"`
	Rationale         string   `yaml:"rationale"`
	Owner             string   `yaml:"owner"`
	Approval          string   `yaml:"approval"`
	Created           string   `yaml:"created"`
	Expires           string   `yaml:"expires"`
	VerificationTests []string `yaml:"verification-tests,omitempty"`
}

type indexedEntry struct {
	index int
	entry Entry
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
	candidates := make([]indexedEntry, 0, len(document.Exceptions))
	for index, wire := range document.Exceptions {
		entry, entryIssues := validateEntry(index, wire, currentDate)
		issues = append(issues, entryIssues...)
		if len(entryIssues) == 0 {
			candidates = append(candidates, indexedEntry{index: index, entry: entry})
		}
	}

	counts := make(map[string]int, len(candidates))
	for _, candidate := range candidates {
		counts[candidate.entry.Identity()]++
	}
	entries := make([]Entry, 0, len(candidates))
	for _, candidate := range candidates {
		if counts[candidate.entry.Identity()] > 1 {
			issues = append(issues, Issue{Index: candidate.index, Code: "duplicate-exception", Detail: candidate.entry.Identity()})
			continue
		}
		entries = append(entries, candidate.entry)
	}
	slices.SortFunc(entries, func(left, right Entry) int { return strings.Compare(left.Identity(), right.Identity()) })
	sortIssues(issues)
	return Set{Entries: entries}, issues, nil
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
