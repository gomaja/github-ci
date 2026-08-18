package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/github-ci/internal/evidence"
	"github.com/gomaja/github-ci/internal/gate"
	"github.com/gomaja/github-ci/internal/reports"
)

func TestRunRejectsUnknownAndIncompleteCommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "no command", want: "usage:"},
		{name: "unknown", args: []string{"unknown"}, want: "unknown command"},
		{name: "parse missing tool", args: []string{"parse", "--report", "report.json"}, want: "--tool is required"},
		{name: "parse missing report", args: []string{"parse", "--tool", "sarif"}, want: "--report is required"},
		{name: "generate unknown flag", args: []string{"generate", "--token", "secret-value"}, want: "flag provided but not defined"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), test.args, strings.NewReader(""), &stdout, &stderr, fixedNow)
			if code != 2 {
				t.Fatalf("Run() code = %d, want 2; stderr = %q", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), test.want)
			}
			if strings.Contains(stderr.String(), "secret-value") {
				t.Fatalf("stderr disclosed a flag value: %q", stderr.String())
			}
		})
	}
}

func TestRunRejectsNilContext(t *testing.T) {
	var stderr bytes.Buffer
	var nilContext context.Context
	code := Run(nilContext, nil, strings.NewReader(""), io.Discard, &stderr, fixedNow)
	if code != exitError || !strings.Contains(stderr.String(), "context must not be nil") {
		t.Fatalf("Run(nil) code = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunParseExitCodes(t *testing.T) {
	directory := t.TempDir()
	clean := filepath.Join(directory, "clean.json")
	finding := filepath.Join(directory, "finding.json")
	malformed := filepath.Join(directory, "malformed.json")
	mustWrite(t, clean, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test","rules":[]}},"results":[],"invocations":[{"executionSuccessful":true}]}]}`)
	mustWrite(t, finding, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test","rules":[{"id":"RULE"}]}},"results":[{"ruleId":"RULE","level":"warning","message":{"text":"finding"}}],"invocations":[{"executionSuccessful":true}]}]}`)
	mustWrite(t, malformed, `{`)

	tests := []struct {
		name string
		path string
		code int
		want string
	}{
		{name: "clean", path: clean, code: 0, want: `"findings":0`},
		{name: "finding", path: finding, code: 1, want: `"findings":1`},
		{name: "malformed", path: malformed, code: 2, want: "parse sarif report"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(context.Background(), []string{"parse", "--tool", "sarif", "--report", test.path}, strings.NewReader(""), &stdout, &stderr, fixedNow)
			if code != test.code {
				t.Fatalf("Run() code = %d, want %d; stdout = %q stderr = %q", code, test.code, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			if !strings.Contains(combined, test.want) {
				t.Fatalf("output = %q, want substring %q", combined, test.want)
			}
		})
	}
}

func TestRunHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	code := Run(ctx, []string{"generate", "--root", t.TempDir()}, strings.NewReader(""), &stdout, &stderr, fixedNow)
	if code != 2 || !strings.Contains(stderr.String(), "context canceled") {
		t.Fatalf("Run() code = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunFilesClassifiesTrackedRepository(t *testing.T) {
	repository := newRepository(t)
	files := map[string]string{
		"data/config.json":         "{}\n",
		"deploy/main.tf":           "terraform {}\n",
		"docs/guide.md":            "# Guide\n",
		"images/Dockerfile":        "FROM scratch\n",
		"scripts/check.sh":         "#!/bin/sh\ntrue\n",
		"settings/config.yaml":     "enabled: true\n",
		".github/workflows/ci.yml": "on: push\n",
	}
	for name, contents := range files {
		path := filepath.Join(repository, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		mustWrite(t, path, contents)
	}
	command := exec.CommandContext(t.Context(), "git", "add", ".")
	command.Dir = repository
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git add fixtures: %v: %s", err, output)
	}

	want := map[string]string{
		"docker":    "images/Dockerfile\x00",
		"json":      "data/config.json\x00",
		"markdown":  "README.md\x00docs/guide.md\x00",
		"shell":     "scripts/check.sh\x00",
		"terraform": "deploy/main.tf\x00",
		"workflow":  ".github/workflows/ci.yml\x00",
		"yaml":      ".github/github-ci.yaml\x00.github/workflows/ci.yml\x00settings/config.yaml\x00",
	}
	for kind, expected := range want {
		code, stdout, stderr := runForTest(t, []string{"files", "--repository", repository, "--config", ".github/github-ci.yaml", "--kind", kind})
		if code != 0 || stdout != expected {
			t.Errorf("files %s: code = %d, stdout = %q, stderr = %q; want %q", kind, code, stdout, stderr, expected)
		}
	}
}

func TestDiagnosticsAreDeterministic(t *testing.T) {
	run := func() string {
		var stdout, stderr bytes.Buffer
		code := Run(context.Background(), []string{"parse", "--tool", "unknown", "--report", filepath.Join(t.TempDir(), "missing")}, strings.NewReader(""), &stdout, &stderr, fixedNow)
		if code != 2 {
			t.Fatalf("Run() code = %d", code)
		}
		return strings.ReplaceAll(stderr.String(), filepath.Dir(filepath.Dir(stderr.String())), "")
	}
	first := run()
	second := run()
	if first != second {
		t.Fatalf("diagnostics differ:\nfirst: %q\nsecond: %q", first, second)
	}
}

func TestPreflightRecordAndGateEndToEnd(t *testing.T) {
	repository := newRepository(t)
	artifacts := t.TempDir()
	policy := filepath.Clean(filepath.Join("..", "..", "policies", "tools.yaml"))
	planPath := filepath.Join(artifacts, "plan.json")
	configPath := ".github/github-ci.yaml"

	code, _, stderr := runForTest(t, []string{
		"preflight", "--repository", repository, "--config", configPath,
		"--policy", policy, "--output", planPath,
	})
	if code != 0 {
		t.Fatalf("preflight code = %d, stderr = %q", code, stderr)
	}
	plan, err := readPlan(planPath)
	if err != nil {
		t.Fatalf("readPlan() error = %v", err)
	}
	if len(plan.Expected) == 0 {
		t.Fatal("preflight emitted an empty plan")
	}

	naPath := filepath.Join(artifacts, "na.json")
	code, _, stderr = runForTest(t, []string{
		"record", "--plan", planPath, "--tool", "shellcheck",
		"--command-id", "shellcheck/scripts", "--tool-version", "0.11.0", "--output", naPath,
	})
	if code != 0 {
		t.Fatalf("N/A record code = %d, stderr = %q", code, stderr)
	}

	markdownReport := filepath.Join(artifacts, "markdownlint.json")
	mustWrite(t, markdownReport, `{"schema_version":"1","paths":[]}`)
	markdownRecord := filepath.Join(artifacts, "markdownlint-record.json")
	code, _, stderr = runForTest(t, []string{
		"record", "--plan", planPath, "--tool", "markdownlint",
		"--command-id", "markdownlint/documents", "--tool-version", "0.23.2",
		"--report", markdownReport, "--output", markdownRecord,
	})
	if code != 0 {
		t.Fatalf("applicable record code = %d, stderr = %q", code, stderr)
	}
	code, _, stderr = runForTest(t, []string{
		"record", "--plan", planPath, "--tool", "markdownlint",
		"--command-id", "markdownlint/documents", "--tool-version", "0.23.2",
		"--parser-tool", "sarif", "--report", markdownReport, "--output", markdownRecord,
	})
	if code != 2 || !strings.Contains(stderr, "must be \"path-list\"") {
		t.Fatalf("wrong parser code = %d, stderr = %q", code, stderr)
	}

	manifest, reportToTamper := cleanEvidenceSet(t, plan, artifacts)
	manifestPath := filepath.Join(artifacts, "manifest.json")
	writeTestJSON(t, manifestPath, manifest)
	gateArgs := []string{
		"gate", "--repository", repository, "--config", configPath, "--policy", policy,
		"--plan", planPath, "--manifest", manifestPath,
	}
	code, stdout, stderr := runForTest(t, gateArgs)
	if code != 0 || !strings.Contains(stdout, `"pass":true`) {
		t.Fatalf("gate code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}

	originalReport, err := os.ReadFile(reportToTamper)
	if err != nil {
		t.Fatalf("read report before tamper: %v", err)
	}
	if err := os.WriteFile(reportToTamper, append(originalReport, '\n'), 0o600); err != nil {
		t.Fatalf("tamper report: %v", err)
	}
	code, stdout, stderr = runForTest(t, gateArgs)
	if code != 1 || !strings.Contains(stdout, "report-hash-mismatch") {
		t.Fatalf("tampered gate code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestModulesApplicabilityAndAggregateCommands(t *testing.T) {
	repository := newRepository(t)
	artifacts := t.TempDir()
	policy := filepath.Clean(filepath.Join("..", "..", "policies", "tools.yaml"))
	planPath := filepath.Join(artifacts, "plan.json")
	code, _, stderr := runForTest(t, []string{
		"preflight", "--repository", repository, "--config", ".github/github-ci.yaml",
		"--policy", policy, "--output", planPath,
	})
	if code != 0 {
		t.Fatalf("preflight code = %d, stderr = %q", code, stderr)
	}
	code, stdout, stderr := runForTest(t, []string{"modules", "--repository", repository, "--config", ".github/github-ci.yaml"})
	if code != 0 || stdout != `{"modules":[]}`+"\n" {
		t.Fatalf("modules code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	code, _, stderr = runForTest(t, []string{"applicable", "--plan", planPath, "--tool", "shellcheck", "--command-id", "shellcheck/scripts"})
	if code != 1 || stderr != "" {
		t.Fatalf("applicable N/A code = %d, stderr = %q", code, stderr)
	}
	code, _, stderr = runForTest(t, []string{"applicable", "--plan", planPath, "--tool", "gitleaks", "--command-id", "gitleaks/content"})
	if code != 0 || stderr != "" {
		t.Fatalf("applicable code = %d, stderr = %q", code, stderr)
	}

	reportA := filepath.Join(artifacts, "a.json")
	reportB := filepath.Join(artifacts, "b.json")
	aggregate := filepath.Join(artifacts, "aggregate.json")
	mustWrite(t, reportA, `{"schema_version":"1","execution_successful":true}`)
	mustWrite(t, reportB, `{"schema_version":"1","execution_successful":false}`)
	code, _, stderr = runForTest(t, []string{
		"aggregate", "--tool", "command-status", "--report", ".=" + reportA,
		"--report", "module-b=" + reportB, "--output", aggregate,
	})
	if code != 0 {
		t.Fatalf("aggregate code = %d, stderr = %q", code, stderr)
	}
	parsed, err := reports.Count("command-status", bytes.NewReader(mustReadFile(t, aggregate)))
	if err != nil || parsed.Findings != 1 {
		t.Fatalf("Count(aggregate) = %#v, %v", parsed, err)
	}
}

func cleanEvidenceSet(t *testing.T, plan evidence.Plan, directory string) (gateManifest, string) {
	t.Helper()
	manifest := gateManifest{SchemaVersion: evidence.SchemaVersion}
	firstApplicableReport := ""
	for index, expected := range plan.Expected {
		recordPath := filepath.Join(directory, fmt.Sprintf("record-%02d.json", index))
		producer := producerWire{
			Tool: expected.Tool, CommandID: expected.CommandID,
			RecordPath: filepath.Base(recordPath), Execution: gate.ExecutionSkipped,
		}
		record := evidence.Record{
			SchemaVersion: evidence.SchemaVersion, Tool: expected.Tool, ToolVersion: "test-version",
			PolicyVersion: plan.PolicySHA256, SubjectSHA: plan.SubjectSHA,
			Applicability: expected.Applicability, CommandID: expected.CommandID,
			Outcome: evidence.OutcomeNotApplicable,
		}
		if expected.Applicability == evidence.Applicable {
			parserTool, ok := reports.ParserTool(expected.ParserVersion)
			if !ok {
				t.Fatalf("no parser for %q", expected.ParserVersion)
			}
			reportPath := filepath.Join(directory, fmt.Sprintf("report-%02d.native", index))
			report := cleanNativeReport(t, parserTool)
			mustWrite(t, reportPath, report)
			record.Outcome = evidence.OutcomePass
			record.ReportSHA256 = testDigest([]byte(report))
			producer.Execution = gate.ExecutionCompleted
			producer.ReportPath = filepath.Base(reportPath)
			if firstApplicableReport == "" {
				firstApplicableReport = reportPath
			}
		}
		if err := evidence.WriteAtomic(recordPath, record); err != nil {
			t.Fatalf("WriteAtomic(%s) error = %v", expected.Identity(), err)
		}
		manifest.Producers = append(manifest.Producers, producer)
	}
	return manifest, firstApplicableReport
}

func cleanNativeReport(t *testing.T, tool string) string {
	t.Helper()
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
		"actionlint":    "actionlint.json",
		"spdx":          "spdx.json",
		"license":       "license.json",
	}
	if fixture, ok := fixtures[tool]; ok {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "reports", "clean", fixture))
		if err != nil {
			t.Fatalf("read %s fixture: %v", tool, err)
		}
		return string(data)
	}
	switch tool {
	case "command-status":
		return `{"schema_version":"1","execution_successful":true}`
	case "path-list":
		return `{"schema_version":"1","paths":[]}`
	case "junit":
		return `<testsuites tests="0" failures="0" errors="0"></testsuites>`
	case "markdownlint":
		return `[]`
	case "yamllint":
		return "{\"schema_version\":\"1\",\"execution_successful\":true}\n"
	default:
		t.Fatalf("no clean report for %q", tool)
		return ""
	}
}

func newRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "README.md"), "# Test repository\n")
	if err := os.MkdirAll(filepath.Join(root, ".github"), 0o755); err != nil {
		t.Fatalf("create .github: %v", err)
	}
	mustWrite(t, filepath.Join(root, ".github", "github-ci.yaml"), "schema-version: 1\nprofile: repository-only\n")
	for _, args := range [][]string{
		{"init", "-b", "main"},
		{"config", "user.name", "gomaja"},
		{"config", "user.email", "marwanjdid@gmail.com"},
		{"add", "."},
		{"commit", "-m", "test: initialize fixture"},
	} {
		command := exec.CommandContext(t.Context(), "git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
		}
	}
	return root
}

func runForTest(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, strings.NewReader(""), &stdout, &stderr, fixedNow)
	return code, stdout.String(), stderr.String()
}

func writeTestJSON(t *testing.T, name string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	if err := os.WriteFile(name, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func testDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", digest)
}

func fixedNow() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }

func mustWrite(t *testing.T, name, contents string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func mustReadFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}
