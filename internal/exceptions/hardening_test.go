package exceptions

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLoadDetailedRejectsEachFingerprintClass(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
	}{
		{name: "invalid syntax", fingerprint: "abcdefgh?"},
		{name: "placeholder", fingerprint: "placeholder"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := strings.Replace(validDocument(), "sha256:0123456789abcdef", test.fingerprint, 1)
			set, issues, err := LoadDetailed(strings.NewReader(document), testNow)
			if err != nil {
				t.Fatalf("LoadDetailed() error = %v", err)
			}
			if len(set.Entries()) != 0 || !hasIssue(issues, "invalid-fingerprint") {
				t.Fatalf("LoadDetailed() set = %#v, issues = %#v", set, issues)
			}
		})
	}
}

func TestLoadDetailedReportsEveryDuplicateFingerprint(t *testing.T) {
	entry := strings.TrimSuffix(strings.SplitN(validDocument(), "exceptions:\n", 2)[1], "\n")
	otherScope := strings.Replace(entry, "scope: internal/parser.go", "scope: internal/other.go", 1)
	document := "schema-version: 1\nexceptions:\n" + entry + "\n" + otherScope + "\n"
	set, issues, err := LoadDetailed(strings.NewReader(document), testNow)
	if err != nil {
		t.Fatalf("LoadDetailed() error = %v", err)
	}
	if len(set.Entries()) != 0 || len(issues) != 2 {
		t.Fatalf("LoadDetailed() set = %#v, issues = %#v", set, issues)
	}
	for index, issue := range issues {
		if issue.Index != index || issue.Code != "duplicate-fingerprint" {
			t.Fatalf("issues[%d] = %#v", index, issue)
		}
	}
}

func TestValidateSetJSONShapeChecksValidatedOnRepresentationsIndependently(t *testing.T) {
	tests := []struct {
		name string
		data json.RawMessage
	}{
		{name: "missing value", data: nil},
		{name: "non-string", data: json.RawMessage("1")},
		{name: "invalid string", data: json.RawMessage(`"\x"`)},
		{name: "empty string", data: json.RawMessage(`""`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateValidatedOnJSON(test.data); err == nil {
				t.Fatal("validateValidatedOnJSON() error = nil")
			}
		})
	}
	if err := validateValidatedOnJSON(json.RawMessage(`"2026-08-18"`)); err != nil {
		t.Fatalf("validateValidatedOnJSON(valid) error = %v", err)
	}
}

func TestParseDateChecksParseAndCanonicalFormIndependently(t *testing.T) {
	if _, err := parseDate("not-a-date"); err == nil {
		t.Fatal("parseDate(invalid) error = nil")
	}
	date, err := parseDate("2026-08-18")
	if err != nil || date.Format("2006-01-02") != "2026-08-18" {
		t.Fatalf("parseDate(valid) = %v, %v", date, err)
	}
}
