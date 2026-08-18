// Package reports counts findings in native analyzer reports.
package reports

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// MaxInputBytes is the hard limit for every native report parser.
const MaxInputBytes = 64 << 20

// Result is a successfully parsed native report summary.
type Result struct {
	Findings int `json:"findings"`
}

// Count parses one bounded native report and counts all findings.
func Count(tool string, reader io.Reader) (Result, error) {
	if reader == nil {
		return Result{}, errors.New("report reader is nil")
	}
	if !IsSupported(tool) {
		return Result{}, fmt.Errorf("unsupported report tool %q", tool)
	}
	data, err := readBounded(reader)
	if err != nil {
		return Result{}, err
	}
	findings, err := countReportData(tool, data)
	if err != nil {
		return Result{}, fmt.Errorf("parse %s report: %w", tool, err)
	}
	return Result{Findings: findings}, nil
}

func countReportData(tool string, data []byte) (int, error) {
	if isAggregate(data) {
		return countAggregate(tool, data)
	}
	return parsers[tool](data)
}

var parsers = map[string]func([]byte) (int, error){
	"command-status": countCommandStatus,
	"path-list":      countPathList,
	"junit":          countJUnit,
	"gopls":          countGopls,
	"markdownlint":   countJSONArray,
	"yamllint":       countYamllint,
	"sarif":          countSARIF,
	"golangci-lint":  countGolangCILint,
	"govulncheck":    countGovulncheck,
	"staticcheck":    countStaticcheck,
	"shellcheck":     countJSONArray,
	"gitleaks":       countJSONArray,
	"osv-scanner":    countOSVScanner,
	"trivy":          countTrivy,
	"grype":          countGrype,
	"semgrep":        countSemgrep,
	"checkov":        countCheckov,
}

var parserTools = map[string]string{
	"sarif/v1":              "sarif",
	"command-status/v1":     "command-status",
	"path-list/v1":          "path-list",
	"gotestsum-junit/v1":    "junit",
	"gopls-diagnostics/v1":  "gopls",
	"markdownlint-json/v1":  "markdownlint",
	"yamllint-parsable/v1":  "yamllint",
	"golangci-lint-json/v1": "golangci-lint",
	"govulncheck-json/v1":   "govulncheck",
	"staticcheck-jsonl/v1":  "staticcheck",
	"shellcheck-json1/v1":   "shellcheck",
	"gitleaks-json/v1":      "gitleaks",
	"osv-json/v1":           "osv-scanner",
	"trivy-json/v1":         "trivy",
	"grype-json/v1":         "grype",
	"semgrep-json/v1":       "semgrep",
	"checkov-json/v1":       "checkov",
}

// IsSupported reports whether tool has a native report parser.
func IsSupported(tool string) bool {
	_, exists := parsers[tool]
	return exists
}

// ParserTool returns the native parser bound to a catalog parser identity.
func ParserTool(parserVersion string) (string, bool) {
	tool, exists := parserTools[parserVersion]
	return tool, exists
}

func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	if len(data) > MaxInputBytes {
		return nil, fmt.Errorf("report exceeds %d byte limit", MaxInputBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty report")
	}
	return data, nil
}
