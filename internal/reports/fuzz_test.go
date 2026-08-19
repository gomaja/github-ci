package reports

import (
	"bytes"
	"testing"
)

func FuzzCountSARIF(f *testing.F) { fuzzReport(f, "sarif", "sarif.json", "sarif.json") }
func FuzzCountScorecardSARIF(f *testing.F) {
	fuzzReport(f, "scorecard-sarif", "scorecard-sarif.json", "scorecard-sarif.json")
}
func FuzzCountGolangCILint(f *testing.F) {
	fuzzReport(f, "golangci-lint", "golangci-lint.json", "golangci-lint.json")
}
func FuzzCountGovulncheck(f *testing.F) {
	fuzzReport(f, "govulncheck", "govulncheck.json", "govulncheck.json")
}
func FuzzCountStaticcheck(f *testing.F) {
	fuzzReport(f, "staticcheck", "staticcheck.jsonl", "staticcheck.jsonl")
}
func FuzzCountShellCheck(f *testing.F) {
	fuzzReport(f, "shellcheck", "shellcheck.json", "shellcheck.json")
}
func FuzzCountGitleaks(f *testing.F) { fuzzReport(f, "gitleaks", "gitleaks.json", "gitleaks.json") }
func FuzzCountOSVScanner(f *testing.F) {
	fuzzReport(f, "osv-scanner", "osv-scanner.json", "osv-scanner.json")
}
func FuzzCountTrivy(f *testing.F)   { fuzzReport(f, "trivy", "trivy.json", "trivy.json") }
func FuzzCountGrype(f *testing.F)   { fuzzReport(f, "grype", "grype.json", "grype.json") }
func FuzzCountSemgrep(f *testing.F) { fuzzReport(f, "semgrep", "semgrep.json", "semgrep.json") }
func FuzzCountCheckov(f *testing.F) { fuzzReport(f, "checkov", "checkov.json", "checkov.json") }
func FuzzCountActionlint(f *testing.F) {
	fuzzReport(f, "actionlint", "actionlint.json", "actionlint.json")
}
func FuzzCountSPDX(f *testing.F) {
	f.Add(reportFixture(f, "clean", "spdx.json"))
	f.Add(reportFixture(f, "malformed", "truncated.json.invalid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := Count("spdx", bytes.NewReader(data))
		if err == nil && result.Findings != 0 {
			t.Fatalf("Count() findings = %d, want 0", result.Findings)
		}
	})
}
func FuzzCountLicense(f *testing.F) {
	fuzzReport(f, "license", "license.json", "license.json")
}

func FuzzCountPolicyRunner(f *testing.F) {
	f.Add("command-status", []byte(`{"schema_version":"1","execution_successful":true}`))
	f.Add("path-list", []byte(`{"schema_version":"1","paths":[]}`))
	f.Add("junit", []byte(`<testsuites tests="0" failures="0" errors="0"></testsuites>`))
	f.Add("markdownlint", []byte(`[]`))
	f.Add("yamllint", []byte("{\"schema_version\":\"1\",\"execution_successful\":true}\n"))
	f.Add("gopls", []byte("{\"schema_version\":\"1\",\"parser\":\"gopls-diagnostics-v1\",\"execution_successful\":true}\n"))
	f.Fuzz(func(t *testing.T, tool string, data []byte) {
		result, err := Count(tool, bytes.NewReader(data))
		if err == nil && result.Findings < 0 {
			t.Fatalf("Count() findings = %d", result.Findings)
		}
	})
}

func FuzzCountAggregate(f *testing.F) {
	var seed bytes.Buffer
	err := WriteAggregate("command-status", []NamedReport{{
		Module: ".",
		Data:   []byte(`{"schema_version":"1","execution_successful":true}`),
	}}, &seed)
	if err != nil {
		f.Fatalf("build aggregate seed: %v", err)
	}
	f.Add(seed.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := Count("command-status", bytes.NewReader(data))
		if err == nil && result.Findings < 0 {
			t.Fatalf("Count() findings = %d", result.Findings)
		}
	})
}

func fuzzReport(f *testing.F, tool, clean, findings string) {
	f.Helper()
	f.Add(reportFixture(f, "clean", clean))
	f.Add(reportFixture(f, "findings", findings))
	f.Add(reportFixture(f, "malformed", "truncated.json.invalid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := Count(tool, bytes.NewReader(data))
		if err == nil && result.Findings < 0 {
			t.Fatalf("Count() findings = %d", result.Findings)
		}
	})
}

type fixtureReader interface {
	Helper()
	Fatalf(string, ...any)
}
