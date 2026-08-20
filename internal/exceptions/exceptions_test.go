package exceptions

import (
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var testNow = time.Date(2026, 8, 18, 15, 30, 0, 0, time.UTC)

func TestLoadDetailedAcceptsReviewedExceptionThroughExpiryDate(t *testing.T) {
	set, issues, err := LoadDetailed(strings.NewReader(validDocument()), testNow)
	if err != nil {
		t.Fatalf("LoadDetailed() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("LoadDetailed() issues = %#v", issues)
	}
	if len(set.Entries()) != 1 {
		t.Fatalf("LoadDetailed() entries = %d, want 1", len(set.Entries()))
	}
	entry := set.Entries()[0]
	if entry.Identity() != "staticcheck/SA1000/sha256:0123456789abcdef/internal/parser.go" {
		t.Fatalf("Identity() = %q", entry.Identity())
	}
	if entry.Expires.String() != "2026-08-18" {
		t.Fatalf("Expires = %q", entry.Expires)
	}
}

func TestLoadDetailedReportsSemanticIssuesDeterministically(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
		code   string
	}{
		{name: "expired day after boundary", mutate: func(document string) string { return document }, code: "expired"},
		{name: "future created", mutate: replace("created: 2026-08-01", "created: 2026-08-19"), code: "future-created"},
		{name: "expiry before creation", mutate: replace("expires: 2026-08-18", "expires: 2026-07-31"), code: "expiry-before-creation"},
		{name: "empty rationale", mutate: replace("rationale: Parser input is validated before this unreachable branch.", "rationale: ''"), code: "invalid-rationale"},
		{name: "placeholder rationale", mutate: replace("rationale: Parser input is validated before this unreachable branch.", "rationale: false positive"), code: "invalid-rationale"},
		{name: "unknown tool", mutate: replace("tool: staticcheck", "tool: unknown-scanner"), code: "unknown-tool"},
		{name: "wildcard scope", mutate: replace("scope: internal/parser.go", "scope: internal/*.go"), code: "wildcard-scope"},
		{name: "root scope", mutate: replace("scope: internal/parser.go", "scope: ."), code: "overbroad-scope"},
		{name: "invalid path", mutate: replace("scope: internal/parser.go", "scope: ../parser.go"), code: "invalid-scope"},
		{name: "missing owner", mutate: replace("owner: gomaja", "owner: ''"), code: "invalid-owner"},
		{name: "placeholder approval", mutate: replace("approval: gomaja/github-ci#12", "approval: approved"), code: "invalid-approval"},
		{name: "missing expiry", mutate: replace("expires: 2026-08-18", "expires: ''"), code: "invalid-expires"},
		{name: "invalid verification path", mutate: replace("internal/parser_test.go", "../parser_test.go"), code: "invalid-verification-test"},
		{name: "control character", mutate: replace("owner: gomaja", "owner: \"gomaja\\u0000\""), code: "invalid-owner"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := testNow
			if test.name == "expired day after boundary" {
				now = testNow.AddDate(0, 0, 1)
			}
			set, issues, err := LoadDetailed(strings.NewReader(test.mutate(validDocument())), now)
			if err != nil {
				t.Fatalf("LoadDetailed() fatal error = %v", err)
			}
			if len(set.Entries()) != 0 {
				t.Fatalf("LoadDetailed() retained invalid entries = %#v", set.Entries())
			}
			if !hasIssue(issues, test.code) {
				t.Fatalf("LoadDetailed() issues = %#v, want code %q", issues, test.code)
			}
		})
	}
}

func TestLoadDetailedAcceptsEquivalentMutantRationale(t *testing.T) {
	document := strings.Replace(validDocument(),
		"Parser input is validated before this unreachable branch.",
		"Equivalent mutant because both branches return the same validated sentinel value.", 1)
	set, issues, err := LoadDetailed(strings.NewReader(document), testNow)
	if err != nil || len(issues) != 0 || len(set.Entries()) != 1 {
		t.Fatalf("LoadDetailed() set = %#v, issues = %#v, error = %v", set, issues, err)
	}
}

func TestLoadDetailedRejectsDuplicateIdentities(t *testing.T) {
	entry := strings.TrimSuffix(strings.SplitN(validDocument(), "exceptions:\n", 2)[1], "\n")
	document := "schema-version: 1\nexceptions:\n" + entry + "\n" + entry + "\n"
	set, issues, err := LoadDetailed(strings.NewReader(document), testNow)
	if err != nil {
		t.Fatalf("LoadDetailed() error = %v", err)
	}
	if len(set.Entries()) != 0 {
		t.Fatalf("LoadDetailed() retained duplicate entries = %#v", set.Entries())
	}
	if !hasIssue(issues, "duplicate-exception") {
		t.Fatalf("LoadDetailed() issues = %#v", issues)
	}
	if len(issues) != 2 || issues[0].Index != 0 || issues[1].Index != 1 {
		t.Fatalf("LoadDetailed() duplicate issues = %#v, want both entry indexes", issues)
	}
}

func TestLoadDetailedRejectsDuplicateFingerprintAcrossScopes(t *testing.T) {
	entry := strings.TrimSuffix(strings.SplitN(validDocument(), "exceptions:\n", 2)[1], "\n")
	otherScope := strings.Replace(entry, "scope: internal/parser.go", "scope: internal/other.go", 1)
	document := "schema-version: 1\nexceptions:\n" + entry + "\n" + otherScope + "\n"
	set, issues, err := LoadDetailed(strings.NewReader(document), testNow)
	if err != nil {
		t.Fatalf("LoadDetailed() error = %v", err)
	}
	if len(set.Entries()) != 0 || !hasIssue(issues, "duplicate-fingerprint") {
		t.Fatalf("LoadDetailed() set = %#v, issues = %#v", set, issues)
	}
}

func TestLoadDetailedRejectsFatalDocuments(t *testing.T) {
	tests := []struct {
		name     string
		document string
	}{
		{name: "empty", document: ""},
		{name: "malformed", document: "schema-version: ["},
		{name: "unknown field", document: "schema-version: 1\nunknown: true\nexceptions: []\n"},
		{name: "duplicate key", document: "schema-version: 1\nschema-version: 1\nexceptions: []\n"},
		{name: "trailing document", document: validDocument() + "---\nexceptions: []\n"},
		{name: "oversized", document: strings.Repeat("#", maxDocumentBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := LoadDetailed(strings.NewReader(test.document), testNow); err == nil {
				t.Fatal("LoadDetailed() error = nil")
			}
		})
	}
}

func TestLoadDetailedEnforcesDocumentSizeBoundary(t *testing.T) {
	base := "schema-version: 1\nexceptions: []\n#"
	exact := base + strings.Repeat("x", maxDocumentBytes-len(base))
	set, issues, err := LoadDetailed(strings.NewReader(exact), testNow)
	if err != nil || len(issues) != 0 || len(set.Entries()) != 0 {
		t.Fatalf("LoadDetailed(exact limit) set = %#v, issues = %#v, error = %v", set, issues, err)
	}

	_, _, err = LoadDetailed(strings.NewReader(exact+"x"), testNow)
	if err == nil || err.Error() != "exception document exceeds 1048576 bytes" {
		t.Fatalf("LoadDetailed(over limit) error = %v", err)
	}
}

func TestLoadDetailedRejectsMultipleDocumentsExactly(t *testing.T) {
	_, _, err := LoadDetailed(strings.NewReader(validDocument()+"---\nexceptions: []\n"), testNow)
	if err == nil || err.Error() != "exception document contains multiple YAML documents" {
		t.Fatalf("LoadDetailed() error = %v", err)
	}
}

func TestLoadDetailedRejectsTrailingJSONValueExactly(t *testing.T) {
	var set Set
	err := set.UnmarshalJSON([]byte(`{"schema_version":1,"entries":[]} {}`))
	if err == nil || err.Error() != "exception JSON contains trailing data" {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
}

func TestSetJSONEnforcesDocumentSizeBoundary(t *testing.T) {
	base := `{"schema_version":1,"entries":[]}`
	exact := []byte(base + strings.Repeat(" ", maxDocumentBytes-len(base)))
	var set Set
	if err := set.UnmarshalJSON(exact); err != nil {
		t.Fatalf("UnmarshalJSON(exact limit) error = %v", err)
	}
	if got := set.Entries(); len(got) != 0 {
		t.Fatalf("json.Unmarshal(exact limit) entries = %#v", got)
	}

	err := set.UnmarshalJSON(append(exact, ' '))
	if err == nil || err.Error() != "exception JSON exceeds 1048576 bytes" {
		t.Fatalf("UnmarshalJSON(over limit) error = %v", err)
	}
}

func TestSetMarshalJSONDistinguishesValidationStates(t *testing.T) {
	encoded, err := (Set{}).MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON(empty set) error = %v", err)
	}
	if got, want := string(encoded), `{"schema_version":1,"entries":[]}`; got != want {
		t.Fatalf("MarshalJSON(empty set) = %s, want %s", got, want)
	}

	_, err = (Set{entries: []Entry{{Tool: "staticcheck"}}}).MarshalJSON()
	if err == nil || err.Error() != "exception set has entries without a validation date" {
		t.Fatalf("MarshalJSON(unvalidated set) error = %v", err)
	}
}

func TestLoadDetailedReportsSchemaIssue(t *testing.T) {
	_, issues, err := LoadDetailed(strings.NewReader("schema-version: 2\nexceptions: []\n"), testNow)
	if err != nil {
		t.Fatalf("LoadDetailed() error = %v", err)
	}
	want := []Issue{{Index: -1, Code: "invalid-schema-version", Detail: "schema-version must be 1"}}
	if !issuesEqual(issues, want) {
		t.Fatalf("LoadDetailed() issues = %#v, want %#v", issues, want)
	}
}

func TestLoadDetailedAcceptsEmptySet(t *testing.T) {
	set, issues, err := LoadDetailed(strings.NewReader("schema-version: 1\nexceptions: []\n"), testNow)
	if err != nil || len(issues) != 0 || len(set.Entries()) != 0 {
		t.Fatalf("LoadDetailed() set = %#v, issues = %#v, error = %v", set, issues, err)
	}
}

func TestLoadFailsWhenDetailedIssuesExist(t *testing.T) {
	if _, err := Load(strings.NewReader(strings.Replace(validDocument(), "tool: staticcheck", "tool: unknown", 1)), testNow); err == nil {
		t.Fatal("Load() error = nil")
	}
}

func TestSetFindExactUsesEveryIdentityField(t *testing.T) {
	set, issues, err := LoadDetailed(strings.NewReader(validDocument()), testNow)
	if err != nil || len(issues) != 0 {
		t.Fatalf("LoadDetailed() issues = %#v, error = %v", issues, err)
	}
	entry := set.Entries()[0]
	if index := set.FindExact(entry.Tool, entry.Rule, entry.Fingerprint, entry.Scope); index != 0 {
		t.Fatalf("FindExact() = %d, want 0", index)
	}
	for _, mismatch := range [][4]string{
		{"shellcheck", entry.Rule, entry.Fingerprint, entry.Scope},
		{entry.Tool, "SA1001", entry.Fingerprint, entry.Scope},
		{entry.Tool, entry.Rule, "sha256:different", entry.Scope},
		{entry.Tool, entry.Rule, entry.Fingerprint, "internal/other.go"},
	} {
		if index := set.FindExact(mismatch[0], mismatch[1], mismatch[2], mismatch[3]); index != -1 {
			t.Fatalf("FindExact(%q) = %d, want -1", mismatch, index)
		}
	}
}

func TestSetEntriesReturnsDeepCopy(t *testing.T) {
	set, issues, err := LoadDetailed(strings.NewReader(validDocument()), testNow)
	if err != nil || len(issues) != 0 {
		t.Fatalf("LoadDetailed() issues = %#v, error = %v", issues, err)
	}
	entries := set.Entries()
	entries[0].Tool = "changed"
	entries[0].VerificationTests[0] = "changed.go"
	again := set.Entries()[0]
	if again.Tool != "staticcheck" || again.VerificationTests[0] != "internal/parser_test.go" {
		t.Fatalf("Entries() exposed internal state: %#v", again)
	}
}

func TestSetJSONRoundTripPreservesValidatedEntries(t *testing.T) {
	set, issues, err := LoadDetailed(strings.NewReader(validDocument()), testNow)
	if err != nil || len(issues) != 0 {
		t.Fatalf("LoadDetailed() issues = %#v, error = %v", issues, err)
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var decoded Set
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got := decoded.Entries(); len(got) != 1 || got[0].Identity() != set.Entries()[0].Identity() {
		t.Fatalf("round-trip entries = %#v", got)
	}
}

func TestSetJSONDistinguishesEmptyValidationStates(t *testing.T) {
	tests := []struct {
		name        string
		document    string
		wantDate    string
		wantFailure bool
	}{
		{name: "canonical empty set", document: `{"schema_version":1,"entries":[]}`},
		{name: "dated empty set", document: `{"schema_version":1,"validated_on":"2026-08-18","entries":[]}`, wantDate: "2026-08-18"},
		{
			name:        "entry without validation date",
			document:    `{"schema_version":1,"entries":[{"tool":"staticcheck","rule":"SA1000","fingerprint":"sha256:0123456789abcdef","scope":"internal/parser.go","rationale":"Parser input is validated before this unreachable branch.","owner":"gomaja","approval":"gomaja/github-ci#12","created":"2026-08-01","expires":"2026-08-18","verification_tests":["internal/parser_test.go"]}]}`,
			wantFailure: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var set Set
			err := json.Unmarshal([]byte(test.document), &set)
			if test.wantFailure {
				if err == nil {
					t.Fatal("json.Unmarshal() error = nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if got := set.ValidatedOn(); got != test.wantDate {
				t.Fatalf("ValidatedOn() = %q, want %q", got, test.wantDate)
			}
			if got := set.Entries(); len(got) != 0 {
				t.Fatalf("Entries() = %#v, want empty", got)
			}
		})
	}
}

func TestSetJSONRejectsUnvalidatedOrAmbiguousData(t *testing.T) {
	set, issues, err := LoadDetailed(strings.NewReader(validDocument()), testNow)
	if err != nil || len(issues) != 0 {
		t.Fatalf("LoadDetailed() issues = %#v, error = %v", issues, err)
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	tests := []string{
		strings.Replace(string(encoded), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		strings.Replace(string(encoded), `"schema_version":1`, `"schema_version":2,"Schema_Version":1`, 1),
		strings.Replace(string(encoded), `"schema_version":1`, `"Schema_Version":1`, 1),
		strings.Replace(string(encoded), `"schema_version":1`, `"schema_version":1,"unknown":true`, 1),
		`{"schema_version":1,"validated_on":"2026-08-18"}`,
		`{"schema_version":1,"validated_on":"2026-08-18","entries":null}`,
		`{"schema_version":1,"validated_on":null,"entries":[]}`,
		string(encoded) + `{}`,
		strings.Replace(string(encoded), `"rationale":"Parser input is validated before this unreachable branch."`, `"rationale":"false positive"`, 1),
		strings.Replace(string(encoded), `"validated_on":"2026-08-18"`, `"validated_on":"2026-09-01"`, 1),
	}
	for index, document := range tests {
		var decoded Set
		if err := json.Unmarshal([]byte(document), &decoded); err == nil {
			t.Errorf("case %d: json.Unmarshal() error = nil", index)
		}
	}
}

func TestSetValidateOnRechecksExpiryAfterSerialization(t *testing.T) {
	set, issues, err := LoadDetailed(strings.NewReader(validDocument()), testNow)
	if err != nil || len(issues) != 0 {
		t.Fatalf("LoadDetailed() issues = %#v, error = %v", issues, err)
	}
	if got := set.ValidatedOn(); got != "2026-08-18" {
		t.Fatalf("ValidatedOn() = %q", got)
	}
	if issues := set.ValidateOn("2026-08-19"); !hasIssue(issues, "expired") {
		t.Fatalf("ValidateOn() issues = %#v", issues)
	}
	issues = set.ValidateOn("invalid")
	want := []Issue{{Index: -1, Code: "invalid-validation-date", Detail: `date "invalid" must use YYYY-MM-DD`}}
	if !issuesEqual(issues, want) {
		t.Fatalf("ValidateOn(invalid) issues = %#v, want %#v", issues, want)
	}
}

func TestLoadDetailedEnforcesRationaleLengthBoundary(t *testing.T) {
	tests := []struct {
		name      string
		rationale string
		wantIssue bool
	}{
		{name: "twenty characters", rationale: "12345678901234567890"},
		{name: "nineteen characters", rationale: "1234567890123456789", wantIssue: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := strings.Replace(validDocument(), "Parser input is validated before this unreachable branch.", test.rationale, 1)
			set, issues, err := LoadDetailed(strings.NewReader(document), testNow)
			if err != nil {
				t.Fatalf("LoadDetailed() error = %v", err)
			}
			if got := hasIssue(issues, "invalid-rationale"); got != test.wantIssue {
				t.Fatalf("invalid-rationale present = %t, want %t; issues = %#v", got, test.wantIssue, issues)
			}
			wantEntries := 1
			if test.wantIssue {
				wantEntries = 0
			}
			if got := len(set.Entries()); got != wantEntries {
				t.Fatalf("Entries() count = %d, want %d", got, wantEntries)
			}
		})
	}
}

func TestLoadDetailedEnforcesMaximumExceptionDuration(t *testing.T) {
	tests := []struct {
		name      string
		expires   string
		wantIssue bool
	}{
		{name: "ninety days", expires: "2026-04-01"},
		{name: "ninety-one days", expires: "2026-04-02", wantIssue: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := strings.Replace(validDocument(), "created: 2026-08-01", "created: 2026-01-01", 1)
			document = strings.Replace(document, "expires: 2026-08-18", "expires: "+test.expires, 1)
			set, issues, err := LoadDetailed(strings.NewReader(document), time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatalf("LoadDetailed() error = %v", err)
			}
			if got := hasIssue(issues, "expiry-too-distant"); got != test.wantIssue {
				t.Fatalf("expiry-too-distant present = %t, want %t; issues = %#v", got, test.wantIssue, issues)
			}
			wantEntries := 1
			if test.wantIssue {
				wantEntries = 0
			}
			if got := len(set.Entries()); got != wantEntries {
				t.Fatalf("Entries() count = %d, want %d", got, wantEntries)
			}
		})
	}
}

func TestRejectDuplicateKeysFindsNestedMapping(t *testing.T) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte("outer:\n  duplicate: first\n  duplicate: second\n"), &node); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	if err := rejectDuplicateKeys(&node); err == nil || err.Error() != `duplicate YAML key "duplicate"` {
		t.Fatalf("rejectDuplicateKeys() error = %v", err)
	}
}

func TestRejectDuplicateJSONKeysEnforcesNestingLimit(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		suffix  string
		depth   int
		wantErr string
	}{
		{name: "array at limit", prefix: "[", suffix: "]", depth: 256},
		{name: "array over limit", prefix: "[", suffix: "]", depth: 257, wantErr: "validate exception JSON: JSON nesting exceeds 256 levels"},
		{name: "object at limit", prefix: `{"value":`, suffix: "}", depth: 256},
		{name: "object over limit", prefix: `{"value":`, suffix: "}", depth: 257, wantErr: "validate exception JSON: JSON nesting exceeds 256 levels"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := strings.Repeat(test.prefix, test.depth) + "0" + strings.Repeat(test.suffix, test.depth)
			err := rejectDuplicateJSONKeys([]byte(document))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("rejectDuplicateJSONKeys() error = %v", err)
				}
				return
			}
			if err == nil || err.Error() != test.wantErr {
				t.Fatalf("rejectDuplicateJSONKeys() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestRejectDuplicateJSONKeysReportsUnclosedArray(t *testing.T) {
	err := rejectDuplicateJSONKeys([]byte("["))
	if err == nil || !strings.HasPrefix(err.Error(), "validate exception JSON: ") {
		t.Fatalf("rejectDuplicateJSONKeys() error = %v", err)
	}
	var syntaxError *json.SyntaxError
	if !errors.Is(err, io.EOF) && !errors.As(err, &syntaxError) {
		t.Fatalf("rejectDuplicateJSONKeys() error cause = %T, want EOF or *json.SyntaxError", err)
	}
}

func TestSortIssuesOrdersEveryIdentityField(t *testing.T) {
	issues := []Issue{
		{Index: 1, Code: "a", Detail: "a"},
		{Index: 0, Code: "b", Detail: "z"},
		{Index: 0, Code: "a", Detail: "z"},
		{Index: 0, Code: "a", Detail: "a"},
	}
	sortIssues(issues)
	want := []Issue{
		{Index: 0, Code: "a", Detail: "a"},
		{Index: 0, Code: "a", Detail: "z"},
		{Index: 0, Code: "b", Detail: "z"},
		{Index: 1, Code: "a", Detail: "a"},
	}
	if !issuesEqual(issues, want) {
		t.Fatalf("sortIssues() = %#v, want %#v", issues, want)
	}
}

func FuzzLoadDetailed(f *testing.F) {
	f.Add([]byte(validDocument()))
	f.Add([]byte("schema-version: 1\nexceptions: ["))
	f.Add([]byte("schema-version: 1\nschema-version: 1\nexceptions: []\n"))
	f.Add([]byte("schema-version: 1\nexceptions: []\n---\n{}\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = LoadDetailed(strings.NewReader(string(data)), testNow)
	})
}

func FuzzSetJSON(f *testing.F) {
	set, issues, err := LoadDetailed(strings.NewReader(validDocument()), testNow)
	if err != nil || len(issues) != 0 {
		f.Fatalf("LoadDetailed() issues = %#v, error = %v", issues, err)
	}
	valid, err := json.Marshal(set)
	if err != nil {
		f.Fatalf("json.Marshal() error = %v", err)
	}
	f.Add(valid)
	f.Add([]byte(`{"schema_version":1,"entries":[]}`))
	f.Add([]byte(`{"schema_version":1,"schema_version":1,"entries":[]}`))
	f.Add([]byte(`{"schema_version":1,"entries":[`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		var candidate Set
		_ = json.Unmarshal(data, &candidate)
	})
}

func validDocument() string {
	return `schema-version: 1
exceptions:
  - tool: staticcheck
    rule: SA1000
    fingerprint: sha256:0123456789abcdef
    scope: internal/parser.go
    rationale: Parser input is validated before this unreachable branch.
    owner: gomaja
    approval: gomaja/github-ci#12
    created: 2026-08-01
    expires: 2026-08-18
    verification-tests:
      - internal/parser_test.go
`
}

func replace(old, replacement string) func(string) string {
	return func(document string) string { return strings.Replace(document, old, replacement, 1) }
}

func hasIssue(issues []Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func issuesEqual(left, right []Issue) bool {
	return slices.Equal(left, right)
}
