package reports

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestCountNativeReports(t *testing.T) {
	tests := []struct {
		tool     string
		fixture  string
		findings int
	}{
		{tool: "sarif", fixture: "sarif.json"},
		{tool: "sarif", fixture: "sarif-levels.json", findings: 4},
		{tool: "golangci-lint", fixture: "golangci-lint.json", findings: 1},
		{tool: "govulncheck", fixture: "govulncheck.json", findings: 1},
		{tool: "staticcheck", fixture: "staticcheck.jsonl", findings: 1},
		{tool: "shellcheck", fixture: "shellcheck.json", findings: 1},
		{tool: "gitleaks", fixture: "gitleaks.json", findings: 1},
		{tool: "osv-scanner", fixture: "osv-scanner.json", findings: 1},
		{tool: "trivy", fixture: "trivy.json", findings: 4},
		{tool: "grype", fixture: "grype.json", findings: 1},
		{tool: "semgrep", fixture: "semgrep.json", findings: 1},
		{tool: "checkov", fixture: "checkov.json", findings: 1},
	}

	for _, test := range tests {
		t.Run(test.tool+"/"+test.fixture, func(t *testing.T) {
			directory := "findings"
			if test.findings == 0 {
				directory = "clean"
			}
			result, err := Count(test.tool, bytes.NewReader(reportFixture(t, directory, test.fixture)))
			if err != nil {
				t.Fatalf("Count() error = %v", err)
			}
			if result.Findings != test.findings {
				t.Fatalf("Count() findings = %d, want %d", result.Findings, test.findings)
			}
		})
	}
}

func TestEveryParserAcceptsCleanFixture(t *testing.T) {
	fixtures := map[string]string{
		"sarif":         "sarif.json",
		"golangci-lint": "golangci-lint.json",
		"govulncheck":   "govulncheck.json",
		"staticcheck":   "staticcheck.jsonl",
		"shellcheck":    "shellcheck.json",
		"gitleaks":      "gitleaks.json",
		"osv-scanner":   "osv-scanner.json",
		"trivy":         "trivy.json",
		"grype":         "grype.json",
		"semgrep":       "semgrep.json",
		"checkov":       "checkov.json",
	}
	for tool, fixture := range fixtures {
		t.Run(tool, func(t *testing.T) {
			result, err := Count(tool, bytes.NewReader(reportFixture(t, "clean", fixture)))
			if err != nil {
				t.Fatalf("Count() error = %v", err)
			}
			if result.Findings != 0 {
				t.Fatalf("Count() findings = %d, want 0", result.Findings)
			}
		})
	}
}

func TestCountRejectsInvalidInput(t *testing.T) {
	for _, tool := range supportedTools() {
		t.Run(tool+"/empty", func(t *testing.T) {
			_, err := Count(tool, strings.NewReader(" \n\t"))
			if err == nil || !strings.Contains(err.Error(), "empty") {
				t.Fatalf("Count() error = %v, want empty input error", err)
			}
		})
		t.Run(tool+"/truncated", func(t *testing.T) {
			_, err := Count(tool, bytes.NewReader(reportFixture(t, "malformed", "truncated.json")))
			if err == nil {
				t.Fatal("Count() accepted truncated input")
			}
		})
	}

	t.Run("unknown tool", func(t *testing.T) {
		_, err := Count("unknown", strings.NewReader("{}"))
		if err == nil || !strings.Contains(err.Error(), "unsupported report tool") {
			t.Fatalf("Count() error = %v", err)
		}
	})
	t.Run("nil reader", func(t *testing.T) {
		_, err := Count("sarif", nil)
		if err == nil || !strings.Contains(err.Error(), "nil") {
			t.Fatalf("Count() error = %v", err)
		}
	})
}

func TestCountRejectsOversizedInput(t *testing.T) {
	reader := io.MultiReader(
		bytes.NewReader(reportFixture(t, "clean", "sarif.json")),
		io.LimitReader(repeatingReader(' '), MaxInputBytes),
	)
	_, err := Count("sarif", reader)
	if err == nil || !strings.Contains(err.Error(), "exceeds 67108864 byte limit") {
		t.Fatalf("Count() error = %v, want size limit error", err)
	}
}

func TestCountSARIFRejectsUnknownField(t *testing.T) {
	_, err := Count("sarif", bytes.NewReader(reportFixture(t, "malformed", "sarif-unknown-field.json")))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Count() error = %v, want unknown field", err)
	}
}

func TestCountSARIFRejectsDuplicateResult(t *testing.T) {
	_, err := Count("sarif", bytes.NewReader(reportFixture(t, "malformed", "sarif-duplicate-result.json")))
	if err == nil || !strings.Contains(err.Error(), "duplicate SARIF result") {
		t.Fatalf("Count() error = %v, want duplicate result", err)
	}
}

func TestCountSARIFCountsEveryRun(t *testing.T) {
	result, err := Count("sarif", bytes.NewReader(reportFixture(t, "findings", "sarif-multi-run.json")))
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if result.Findings != 3 {
		t.Fatalf("Count() findings = %d, want 3", result.Findings)
	}
}

func TestCountReturnsParserErrorsSeparatelyFromFindings(t *testing.T) {
	for _, test := range []struct {
		tool    string
		fixture string
	}{
		{tool: "semgrep", fixture: "semgrep-error.json"},
		{tool: "checkov", fixture: "checkov-error.json"},
	} {
		t.Run(test.tool, func(t *testing.T) {
			result, err := Count(test.tool, bytes.NewReader(reportFixture(t, "malformed", test.fixture)))
			if err == nil {
				t.Fatal("Count() accepted native parser errors")
			}
			if result.Findings != 0 {
				t.Fatalf("Count() findings = %d after parser error, want 0", result.Findings)
			}
		})
	}
}

func TestCountRejectsIncompleteNativeEnvelope(t *testing.T) {
	tests := []struct {
		name string
		tool string
		json string
	}{
		{name: "golangci-lint report", tool: "golangci-lint", json: `{"Issues":[]}`},
		{name: "repeated govulncheck config", tool: "govulncheck", json: "{\"config\":{\"protocol_version\":\"v1.0.0\"}}\n{\"config\":{\"protocol_version\":\"v1.0.0\"}}"},
		{name: "null govulncheck progress", tool: "govulncheck", json: "{\"config\":{\"protocol_version\":\"v1.0.0\"}}\n{\"progress\":null}"},
		{name: "trivy schema", tool: "trivy", json: `{"Results":[]}`},
		{name: "grype metadata", tool: "grype", json: `{"matches":[]}`},
		{name: "checkov summary", tool: "checkov", json: `{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[],"parsing_errors":[]}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Count(test.tool, strings.NewReader(test.json))
			if err == nil {
				t.Fatal("Count() accepted an incomplete native report envelope")
			}
		})
	}
}

func reportFixture(t fixtureReader, class, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/reports/" + class + "/" + name)
	if err != nil {
		t.Fatalf("read fixture %s/%s: %v", class, name, err)
	}
	return data
}

func supportedTools() []string {
	return []string{"sarif", "golangci-lint", "govulncheck", "staticcheck", "shellcheck", "gitleaks", "osv-scanner", "trivy", "grype", "semgrep", "checkov"}
}

type repeatingReader byte

func (reader repeatingReader) Read(data []byte) (int, error) {
	for index := range data {
		data[index] = byte(reader)
	}
	return len(data), nil
}
