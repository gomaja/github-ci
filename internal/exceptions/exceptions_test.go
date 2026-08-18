package exceptions

import (
	"strings"
	"testing"
	"time"
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

func TestLoadDetailedReportsSchemaIssue(t *testing.T) {
	_, issues, err := LoadDetailed(strings.NewReader("schema-version: 2\nexceptions: []\n"), testNow)
	if err != nil {
		t.Fatalf("LoadDetailed() error = %v", err)
	}
	if !hasIssue(issues, "invalid-schema-version") {
		t.Fatalf("LoadDetailed() issues = %#v", issues)
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

func FuzzLoadDetailed(f *testing.F) {
	f.Add([]byte(validDocument()))
	f.Add([]byte("schema-version: 1\nexceptions: ["))
	f.Add([]byte("schema-version: 1\nschema-version: 1\nexceptions: []\n"))
	f.Add([]byte("schema-version: 1\nexceptions: []\n---\n{}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = LoadDetailed(strings.NewReader(string(data)), testNow)
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

func replace(old, new string) func(string) string {
	return func(document string) string { return strings.Replace(document, old, new, 1) }
}

func hasIssue(issues []Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
