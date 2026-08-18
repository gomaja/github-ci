package reports

import (
	"bytes"
	"testing"
)

func FuzzCountSARIF(f *testing.F) { fuzzReport(f, "sarif", "sarif.json", "sarif.json") }
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

func fuzzReport(f *testing.F, tool, clean, findings string) {
	f.Helper()
	f.Add(reportFixture(f, "clean", clean))
	f.Add(reportFixture(f, "findings", findings))
	f.Add(reportFixture(f, "malformed", "truncated.json"))
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
