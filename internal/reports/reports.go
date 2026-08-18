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
	Findings int
}

// Count parses one bounded native report and counts all findings.
func Count(tool string, reader io.Reader) (Result, error) {
	if reader == nil {
		return Result{}, errors.New("report reader is nil")
	}
	parser, exists := parsers[tool]
	if !exists {
		return Result{}, fmt.Errorf("unsupported report tool %q", tool)
	}
	data, err := readBounded(reader)
	if err != nil {
		return Result{}, err
	}
	findings, err := parser(data)
	if err != nil {
		return Result{}, fmt.Errorf("parse %s report: %w", tool, err)
	}
	return Result{Findings: findings}, nil
}

var parsers = map[string]func([]byte) (int, error){
	"sarif":         countSARIF,
	"golangci-lint": countGolangCILint,
	"govulncheck":   countGovulncheck,
	"staticcheck":   countStaticcheck,
	"shellcheck":    countJSONArray,
	"gitleaks":      countJSONArray,
	"osv-scanner":   countOSVScanner,
	"trivy":         countTrivy,
	"grype":         countGrype,
	"semgrep":       countSemgrep,
	"checkov":       countCheckov,
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
