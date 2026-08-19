package reports

import (
	"strings"
	"testing"
)

func TestCountPolicyRunnerReports(t *testing.T) {
	tests := []struct {
		tool     string
		report   string
		findings int
	}{
		{tool: "command-status", report: `{"schema_version":"1","execution_successful":true}`},
		{tool: "command-status", report: `{"schema_version":"1","execution_successful":false}`, findings: 1},
		{tool: "path-list", report: `{"schema_version":"1","paths":[]}`},
		{tool: "path-list", report: `{"schema_version":"1","paths":["a.go","b.go"]}`, findings: 2},
		{tool: "junit", report: `<testsuites tests="2" failures="1" errors="1"><testsuite name="pkg" tests="2" failures="1" errors="1"></testsuite></testsuites>`, findings: 2},
		{tool: "junit", report: `<testsuites tests="1"><testsuite name="pkg" tests="1"></testsuite></testsuites>`},
		{tool: "markdownlint", report: `[]`},
		{tool: "markdownlint", report: `[{"fileName":"README.md","lineNumber":1,"ruleNames":["MD001"],"ruleDescription":"heading","ruleInformation":"x","errorDetail":null,"errorContext":null,"errorRange":null,"fixInfo":null}]`, findings: 1},
		{tool: "yamllint", report: "{\"schema_version\":\"1\",\"execution_successful\":true}\n"},
		{tool: "yamllint", report: "{\"schema_version\":\"1\",\"execution_successful\":true}\n.github/test.yml:1:1: [warning] missing document start (document-start)\n", findings: 1},
		{tool: "gopls", report: "{\"schema_version\":\"1\",\"parser\":\"gopls-diagnostics-v1\",\"execution_successful\":true}\n"},
		{tool: "gopls", report: "{\"schema_version\":\"1\",\"parser\":\"gopls-diagnostics-v1\",\"execution_successful\":true}\nbroken.go:3:14-15: expected ')'\n", findings: 1},
	}
	for _, test := range tests {
		t.Run(test.tool, func(t *testing.T) {
			result, err := Count(test.tool, strings.NewReader(test.report))
			if err != nil {
				t.Fatalf("Count() error = %v", err)
			}
			if result.Findings != test.findings {
				t.Fatalf("Count() findings = %d, want %d", result.Findings, test.findings)
			}
		})
	}
}

func TestCountPolicyRunnerReportsRejectMalformedInput(t *testing.T) {
	tests := []struct {
		tool   string
		report string
	}{
		{tool: "command-status", report: `{"schema_version":"1","execution_successful":true,"unknown":1}`},
		{tool: "path-list", report: `{"schema_version":"1","paths":["../escape"]}`},
		{tool: "junit", report: `<testsuites tests="1" failures="2"></testsuites>`},
		{tool: "markdownlint", report: `[null]`},
		{tool: "yamllint", report: "{\"schema_version\":\"1\",\"execution_successful\":false}\n"},
		{tool: "gopls", report: "{\"schema_version\":\"1\",\"parser\":\"gopls-diagnostics-v1\",\"execution_successful\":false}\n"},
	}
	for _, test := range tests {
		t.Run(test.tool, func(t *testing.T) {
			if _, err := Count(test.tool, strings.NewReader(test.report)); err == nil {
				t.Fatal("Count() accepted malformed input")
			}
		})
	}
}

func TestParserToolBindsCatalogIdentity(t *testing.T) {
	tests := map[string]string{
		"sarif/v1":              "sarif",
		"scorecard-sarif/v1":    "scorecard-sarif",
		"command-status/v1":     "command-status",
		"path-list/v1":          "path-list",
		"gotestsum-junit/v1":    "junit",
		"gopls-diagnostics/v1":  "gopls",
		"markdownlint-json/v1":  "markdownlint",
		"yamllint-parsable/v1":  "yamllint",
		"golangci-lint-json/v1": "golangci-lint",
		"govulncheck-json/v1":   "govulncheck",
		"staticcheck-jsonl/v1":  "staticcheck",
		"shellcheck-json/v1":    "shellcheck",
		"gitleaks-json/v1":      "gitleaks",
		"osv-json/v1":           "osv-scanner",
		"trivy-json/v1":         "trivy",
		"grype-json/v1":         "grype",
		"semgrep-json/v1":       "semgrep",
		"checkov-json/v1":       "checkov",
	}
	for parser, want := range tests {
		got, ok := ParserTool(parser)
		if !ok || got != want {
			t.Fatalf("ParserTool(%q) = %q, %t; want %q, true", parser, got, ok, want)
		}
	}
	if _, ok := ParserTool("unknown/v1"); ok {
		t.Fatal("ParserTool() accepted unknown parser")
	}
}
