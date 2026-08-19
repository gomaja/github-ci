package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/gomaja/github-ci/internal/config"
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

func TestNormalizeDependenciesDefaultsNilInputs(t *testing.T) {
	dependencies := normalizeDependencies(nil, nil, nil, nil)
	if _, err := dependencies.stdin.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("default stdin Read() error = %v, want EOF", err)
	}
	if dependencies.now().IsZero() {
		t.Fatal("default clock returned the zero time")
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

func TestBuildRecordKeepsRawCodeQLReportDigest(t *testing.T) {
	report := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[{"level":"warning","message":{"text":""}}]}],"results":[]}]}`)
	reportPath := filepath.Join(t.TempDir(), "codeql.sarif")
	if err := os.WriteFile(reportPath, report, 0o600); err != nil {
		t.Fatalf("write CodeQL report: %v", err)
	}
	plan := evidence.Plan{
		PolicySHA256: testDigest([]byte("policy")),
		SubjectSHA:   "0123456789abcdef0123456789abcdef01234567",
		Expected: []evidence.Expected{{
			Tool: "codeql", CommandID: "codeql/go", ParserVersion: "sarif/v1",
			Applicability: evidence.Applicable,
		}},
	}
	record, err := buildRecord(plan, recordOptions{
		tool: "codeql", commandID: "codeql/go", toolVersion: "4.37.7", reportPath: reportPath,
	})
	if err != nil {
		t.Fatalf("buildRecord() error = %v", err)
	}
	if record.ReportSHA256 != testDigest(report) {
		t.Fatalf("report digest = %q, want raw digest %q", record.ReportSHA256, testDigest(report))
	}
	if record.Outcome != evidence.OutcomePass || record.FindingCount != 0 {
		t.Fatalf("record = %#v, want clean pass", record)
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

func TestReleaseEvidenceCommandsEndToEnd(t *testing.T) {
	root := releaseFixture(t)
	output := t.TempDir()
	manifest := filepath.Join(output, "release-manifest.json")
	checksums := filepath.Join(output, "SHA256SUMS")
	args := []string{
		"release-evidence", "--root", root,
		"--subject-sha", strings.Repeat("a", 40),
		"--source-date", "2026-08-19T12:34:56Z",
		"--asset", "dist/github-ci", "--manifest", manifest, "--checksums", checksums,
	}
	code, _, stderr := runForTest(t, args)
	if code != exitSuccess {
		t.Fatalf("release-evidence code = %d, stderr = %q", code, stderr)
	}
	code, _, stderr = runForTest(t, []string{
		"verify-release-evidence", "--root", root, "--manifest", manifest, "--checksums", checksums,
	})
	if code != exitSuccess {
		t.Fatalf("verify-release-evidence code = %d, stderr = %q", code, stderr)
	}

	mustWrite(t, filepath.Join(root, "dist", "github-ci"), "tampered")
	code, _, stderr = runForTest(t, []string{
		"verify-release-evidence", "--root", root, "--manifest", manifest, "--checksums", checksums,
	})
	if code != exitError || !strings.Contains(stderr, "does not match manifest") {
		t.Fatalf("tampered verify code = %d, stderr = %q", code, stderr)
	}
}

func TestRunValidateGremlinsBindsCompleteReportToModule(t *testing.T) {
	report := filepath.Join("..", "..", "testdata", "reports", "clean", "gremlins.json")
	code, _, stderr := runForTest(t, []string{"validate-gremlins", "--report", report, "--module", "example.com/module"})
	if code != exitSuccess || stderr != "" {
		t.Fatalf("validate-gremlins code = %d, stderr = %q", code, stderr)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing report", args: []string{"validate-gremlins", "--module", "example.com/module"}, want: "--report is required"},
		{name: "missing module", args: []string{"validate-gremlins", "--report", report}, want: "--module is required"},
		{name: "positional", args: []string{"validate-gremlins", "--report", report, "--module", "example.com/module", "extra"}, want: "unexpected positional argument"},
		{name: "missing file", args: []string{"validate-gremlins", "--report", filepath.Join(t.TempDir(), "missing"), "--module", "example.com/module"}, want: "open Gremlins report"},
		{name: "wrong module", args: []string{"validate-gremlins", "--report", report, "--module", "example.com/other"}, want: "go_module"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, _, stderr := runForTest(t, test.args)
			if code != exitError || !strings.Contains(stderr, test.want) {
				t.Fatalf("code = %d, stderr = %q, want %q", code, stderr, test.want)
			}
		})
	}
}

func TestRunValidateGremlinsNoResultsWritesEvidence(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gremlins.log")
	outputPath := filepath.Join(t.TempDir(), "nested", "no-results.json")
	mustWrite(t, logPath, "Starting...\n\nNo results to report.\n")
	code, _, stderr := runForTest(t, []string{
		"validate-gremlins-no-results", "--log", logPath, "--module", "example.com/module", "--output", outputPath,
	})
	if code != exitSuccess || stderr != "" {
		t.Fatalf("validate-gremlins-no-results code = %d, stderr = %q", code, stderr)
	}
	var evidence reports.GremlinsNoResultsEvidence
	if err := json.Unmarshal(mustReadFile(t, outputPath), &evidence); err != nil {
		t.Fatalf("decode no-results evidence: %v", err)
	}
	if evidence.GoModule != "example.com/module" || evidence.Outcome != "no-mutants" {
		t.Fatalf("no-results evidence = %#v", evidence)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing log", args: []string{"validate-gremlins-no-results", "--module", "example.com/module", "--output", outputPath}, want: "--log is required"},
		{name: "missing module", args: []string{"validate-gremlins-no-results", "--log", logPath, "--output", outputPath}, want: "--module is required"},
		{name: "missing output", args: []string{"validate-gremlins-no-results", "--log", logPath, "--module", "example.com/module"}, want: "--output is required"},
		{name: "positional", args: []string{"validate-gremlins-no-results", "--log", logPath, "--module", "example.com/module", "--output", outputPath, "extra"}, want: "unexpected positional argument"},
		{name: "missing file", args: []string{"validate-gremlins-no-results", "--log", filepath.Join(t.TempDir(), "missing"), "--module", "example.com/module", "--output", outputPath}, want: "open Gremlins log"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, _, stderr := runForTest(t, test.args)
			if code != exitError || !strings.Contains(stderr, test.want) {
				t.Fatalf("code = %d, stderr = %q, want %q", code, stderr, test.want)
			}
		})
	}
}

func TestReleaseEvidenceCommandsRejectInvalidInput(t *testing.T) {
	root := releaseFixture(t)
	output := t.TempDir()
	valid := []string{
		"--root", root, "--subject-sha", strings.Repeat("b", 40), "--source-date", "2026-08-19T12:34:56Z",
		"--asset", "dist/github-ci", "--manifest", filepath.Join(output, "manifest.json"), "--checksums", filepath.Join(output, "SHA256SUMS"),
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown flag", args: []string{"release-evidence", "--unknown"}, want: "flag provided but not defined"},
		{name: "positional", args: append([]string{"release-evidence"}, append(valid, "extra")...), want: "unexpected positional argument"},
		{name: "required", args: []string{"release-evidence"}, want: "--subject-sha is required"},
		{name: "source date", args: append([]string{"release-evidence"}, replaceArgument(valid, "--source-date", "invalid")...), want: "parse --source-date"},
		{name: "build", args: append([]string{"release-evidence"}, replaceArgument(valid, "--subject-sha", "invalid")...), want: "subject SHA"},
		{name: "write", args: append([]string{"release-evidence"}, replaceArgument(valid, "--manifest", output)...), want: "rename"},
		{name: "verify positional", args: []string{"verify-release-evidence", "--manifest", "manifest", "--checksums", "sums", "extra"}, want: "unexpected positional argument"},
		{name: "verify required", args: []string{"verify-release-evidence"}, want: "--manifest is required"},
		{name: "verify missing", args: []string{"verify-release-evidence", "--manifest", "missing", "--checksums", "missing"}, want: "read release manifest"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, _, stderr := runForTest(t, test.args)
			if code != exitError || !strings.Contains(stderr, test.want) {
				t.Fatalf("code = %d, stderr = %q, want %q", code, stderr, test.want)
			}
		})
	}
}

func TestRunGenerateRejectsInvalidState(t *testing.T) {
	var stderr bytes.Buffer
	if code := runGenerate(context.Background(), []string{"extra"}, &stderr, false); code != exitError || !strings.Contains(stderr.String(), "unexpected positional argument") {
		t.Fatalf("runGenerate(positional) code = %d, stderr = %q", code, stderr.String())
	}
	stderr.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := runGenerate(ctx, nil, &stderr, false); code != exitError || !strings.Contains(stderr.String(), "context canceled") {
		t.Fatalf("runGenerate(cancelled) code = %d, stderr = %q", code, stderr.String())
	}
	stderr.Reset()
	if code := runGenerate(context.Background(), []string{"--root", filepath.Join(t.TempDir(), "missing")}, &stderr, false); code != exitError || !strings.Contains(stderr.String(), "open tool policy") {
		t.Fatalf("runGenerate(missing) code = %d, stderr = %q", code, stderr.String())
	}
	stderr.Reset()
	if code := runGenerate(context.Background(), []string{"--root", filepath.Join("..", "..")}, &stderr, true); code != exitSuccess || stderr.Len() != 0 {
		t.Fatalf("runGenerate(verify) code = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunFilesClassifiesTrackedRepository(t *testing.T) {
	repository := newRepository(t)
	mustWrite(t, filepath.Join(repository, ".github", "github-ci.yaml"), "schema-version: 1\nprofile: repository-only\ngenerated:\n  - generated\n")
	files := map[string]string{
		"main.go":                   "package fixture\n",
		"generated/main.go":         "package generated\n",
		"data/config.json":          "{}\n",
		"deploy/main.tf":            "terraform {}\n",
		"docs/guide.md":             "# Guide\n",
		"images/Dockerfile":         "FROM scratch\n",
		"scripts/check.sh":          "#!/bin/sh\ntrue\n",
		"scripts/check":             "#!/usr/bin/env bash\ntrue\n",
		"settings/config.yaml":      "enabled: true\n",
		".github/workflows/ci.yml":  "on: push\n",
		".github/workflows/ci.yaml": "on: pull_request\n",
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
		"all-go":    "generated/main.go\x00main.go\x00",
		"docker":    "images/Dockerfile\x00",
		"go":        "main.go\x00",
		"json":      "data/config.json\x00",
		"markdown":  "README.md\x00docs/guide.md\x00",
		"shell":     "scripts/check\x00scripts/check.sh\x00",
		"terraform": "deploy/main.tf\x00",
		"workflow":  ".github/workflows/ci.yaml\x00.github/workflows/ci.yml\x00",
		"yaml":      ".github/github-ci.yaml\x00.github/workflows/ci.yaml\x00.github/workflows/ci.yml\x00settings/config.yaml\x00",
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
	gateOutput := filepath.Join(artifacts, "gate-result.json")
	code, stdout, stderr = runForTest(t, append(slicesClone(gateArgs), "--output", gateOutput))
	if code != exitSuccess || stdout != "" || !strings.Contains(string(mustReadFile(t, gateOutput)), `"pass":true`) {
		t.Fatalf("gate output code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	code, _, stderr = runForTest(t, append(slicesClone(gateArgs), "--output", artifacts))
	if code != exitError || stderr == "" {
		t.Fatalf("gate bad output code = %d, stderr = %q", code, stderr)
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

func TestCompareGateFindingsUsesEveryIdentityField(t *testing.T) {
	base := gate.Finding{Tool: "tool", CommandID: "command", Code: "code", Detail: "detail"}
	mutations := []gate.Finding{
		{Tool: "u", CommandID: base.CommandID, Code: base.Code, Detail: base.Detail},
		{Tool: base.Tool, CommandID: "d", Code: base.Code, Detail: base.Detail},
		{Tool: base.Tool, CommandID: base.CommandID, Code: "d", Detail: base.Detail},
		{Tool: base.Tool, CommandID: base.CommandID, Code: base.Code, Detail: "e"},
	}
	if got := compareGateFindings(base, base); got != 0 {
		t.Fatalf("compareGateFindings(equal) = %d", got)
	}
	for index, greater := range mutations {
		if got := compareGateFindings(base, greater); got >= 0 {
			t.Errorf("field %d forward comparison = %d, want negative", index, got)
		}
		if got := compareGateFindings(greater, base); got <= 0 {
			t.Errorf("field %d reverse comparison = %d, want positive", index, got)
		}
	}
}

func TestLoadGateExceptionsHandlesConfiguredFiles(t *testing.T) {
	valid := filepath.Join(t.TempDir(), "exceptions.yaml")
	mustWrite(t, valid, "schema-version: 1\nexceptions: []\n")
	set, issues, err := loadGateExceptions(context.Background(), "", "", valid, fixedNow())
	if err != nil || len(issues) != 0 || set.ValidatedOn() != "2026-08-18" {
		t.Fatalf("loadGateExceptions(valid) = %#v, %#v, %v", set, issues, err)
	}
	if _, _, err := loadGateExceptions(context.Background(), "", "", filepath.Join(t.TempDir(), "missing"), fixedNow()); err == nil || !strings.Contains(err.Error(), "open exceptions") {
		t.Fatalf("loadGateExceptions(missing) error = %v", err)
	}
	malformed := filepath.Join(t.TempDir(), "exceptions.yaml")
	mustWrite(t, malformed, "schema-version: [")
	if _, _, err := loadGateExceptions(context.Background(), "", "", malformed, fixedNow()); err == nil || !strings.Contains(err.Error(), "decode exceptions") {
		t.Fatalf("loadGateExceptions(malformed) error = %v", err)
	}
	if _, _, err := loadGateExceptions(context.Background(), filepath.Join(t.TempDir(), "missing"), ".github/github-ci.yaml", "", fixedNow()); err == nil || !strings.Contains(err.Error(), "resolve checked-out commit") {
		t.Fatalf("loadGateExceptions(missing repository) error = %v", err)
	}
	repository := newRepository(t)
	if _, _, err := loadGateExceptions(context.Background(), repository, ".github/missing.yaml", "", fixedNow()); err == nil || !strings.Contains(err.Error(), "open tracked consumer configuration") {
		t.Fatalf("loadGateExceptions(missing configuration) error = %v", err)
	}
}

func TestLoadGateExceptionFileReportsCloseFailure(t *testing.T) {
	reader := closeErrorReader{Reader: strings.NewReader("schema-version: 1\nexceptions: []\n")}
	if _, _, err := loadGateExceptionFile(reader, fixedNow()); err == nil || err.Error() != "close exceptions: close failed" {
		t.Fatalf("loadGateExceptionFile() error = %v", err)
	}
}

func TestGeneratedPathUsesExactDirectoryBoundaries(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "generated/file.go", want: true},
		{name: "generated", want: true},
		{name: "generated-other/file.go", want: false},
		{name: "other/file.go", want: false},
	}
	for _, test := range tests {
		if got := generatedPath(test.name, []string{"generated"}); got != test.want {
			t.Errorf("generatedPath(%q) = %t, want %t", test.name, got, test.want)
		}
	}
}

func TestReadStrictJSONFileRejectsTrailingValueExactly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trailing.json")
	mustWrite(t, path, "{} {}")
	var destination map[string]any
	if err := readStrictJSONFile(path, &destination); err == nil || err.Error() != "JSON contains a trailing value" {
		t.Fatalf("readStrictJSONFile() error = %v", err)
	}
}

func TestReadStrictJSONFileEnforcesExactSizeBoundary(t *testing.T) {
	valid := `{"value":"ok"}`
	limit := int64(len(valid))
	path := filepath.Join(t.TempDir(), "boundary.json")
	mustWrite(t, path, valid)
	var destination struct {
		Value string `json:"value"`
	}
	if err := readStrictJSONFileWithLimit(path, &destination, limit); err != nil {
		t.Fatalf("readStrictJSONFileWithLimit(exact) error = %v", err)
	}
	if destination.Value != "ok" {
		t.Fatalf("decoded value = %q, want ok", destination.Value)
	}

	mustWrite(t, path, valid+" ")
	if err := readStrictJSONFileWithLimit(path, &destination, limit); err == nil || err.Error() != fmt.Sprintf("JSON exceeds %d byte limit", limit) {
		t.Fatalf("readStrictJSONFileWithLimit(oversize) error = %v", err)
	}
}

func TestObserveProducerReportRejectsParserMismatch(t *testing.T) {
	directory := t.TempDir()
	mustWrite(t, filepath.Join(directory, "report.json"), `{"schema_version":"1","execution_successful":true}`)
	producer := producerWire{
		Tool: "go", CommandID: "go/build", ReportPath: "report.json", ParserTool: "sarif",
	}
	expected := evidence.Expected{
		Tool: "go", CommandID: "go/build", ParserVersion: "command-status/v1", Applicability: evidence.Applicable,
	}
	report, observations, finding := observeProducerReport(directory, producer, expected, true)
	if report != nil || observations != nil || finding == nil || finding.Code != "parser-mismatch" {
		t.Fatalf("observeProducerReport() = %#v, %#v, %#v", report, observations, finding)
	}
}

func TestPreflightRejectsCheckoutAndProfileMismatches(t *testing.T) {
	repository := newRepository(t)
	policy := filepath.Clean(filepath.Join("..", "..", "policies", "tools.yaml"))
	tests := []struct {
		name  string
		flag  string
		value string
		want  string
	}{
		{name: "subject", flag: "--subject-sha", value: strings.Repeat("f", 40), want: "expected subject does not match"},
		{name: "profile", flag: "--profile", value: "go-strict", want: "does not match requested profile"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, _, stderr := runForTest(t, []string{
				"preflight", "--repository", repository, "--config", ".github/github-ci.yaml",
				"--policy", policy, "--output", filepath.Join(t.TempDir(), "plan.json"), test.flag, test.value,
			})
			if code != exitError || !strings.Contains(stderr, test.want) {
				t.Fatalf("preflight code = %d, stderr = %q, want %q", code, stderr, test.want)
			}
		})
	}
}

func TestConsumerModulesPropagatesWalkErrors(t *testing.T) {
	_, err := consumerModules(readDirErrorFS{}, config.Consumer{Profile: config.ProfileRepositoryOnly})
	if err == nil || !strings.Contains(err.Error(), "fixture read directory") {
		t.Fatalf("consumerModules() error = %v", err)
	}
}

func TestConsumerModulesDetectsImplicitGoModule(t *testing.T) {
	tracked := fstest.MapFS{"go.mod": &fstest.MapFile{Data: []byte("module example.com/test\n")}}
	modules, err := consumerModules(tracked, config.Consumer{Profile: config.ProfileGoStrict})
	if err != nil {
		t.Fatalf("consumerModules() error = %v", err)
	}
	if len(modules) != 1 || modules[0] != "." {
		t.Fatalf("consumerModules() = %#v, want [. ]", modules)
	}
}

func TestReadGateManifestAcceptsEveryExecutionState(t *testing.T) {
	states := []gate.ExecutionState{
		gate.ExecutionCompleted,
		gate.ExecutionFailed,
		gate.ExecutionCancelled,
		gate.ExecutionTimedOut,
		gate.ExecutionSkipped,
	}
	for _, state := range states {
		t.Run(string(state), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			writeTestJSON(t, path, gateManifest{
				SchemaVersion: evidence.SchemaVersion,
				Producers:     []producerWire{{Tool: "tool", CommandID: "command", Execution: state}},
			})
			manifest, err := readGateManifest(path)
			if err != nil {
				t.Fatalf("readGateManifest(%q) error = %v", state, err)
			}
			if len(manifest.Producers) != 1 || manifest.Producers[0].Execution != state {
				t.Fatalf("readGateManifest(%q) = %#v", state, manifest)
			}
		})
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
		"sarif":           "sarif.json",
		"scorecard-sarif": "scorecard-sarif.json",
		"golangci-lint":   "golangci-lint.json",
		"govulncheck":     "govulncheck.json",
		"staticcheck":     "staticcheck.jsonl",
		"shellcheck":      "shellcheck.json",
		"gitleaks":        "gitleaks.json",
		"osv-scanner":     "osv-scanner.json",
		"trivy":           "trivy.json",
		"grype":           "grype.json",
		"semgrep":         "semgrep.json",
		"checkov":         "checkov.json",
		"actionlint":      "actionlint.json",
		"spdx":            "spdx.json",
		"license":         "license.json",
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

func releaseFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		".github/workflows/go.yml": "name: go\n",
		"policies/tools.yaml":      "schema-version: 1\n",
		"schemas/evidence.json":    "{}\n",
		"dist/github-ci":           "binary\n",
	}
	for name, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create release fixture directory: %v", err)
		}
		mustWrite(t, path, contents)
	}
	return root
}

func replaceArgument(args []string, flagName, replacement string) []string {
	result := slicesClone(args)
	for index := range result {
		if result[index] == flagName {
			result[index+1] = replacement
			return result
		}
	}
	return result
}

func slicesClone[T any](values []T) []T { return append([]T(nil), values...) }

type closeErrorReader struct{ io.Reader }

func (closeErrorReader) Close() error { return errors.New("close failed") }

type readDirErrorFS struct{}

func (readDirErrorFS) Open(name string) (fs.File, error) {
	if name != "." {
		return nil, fs.ErrNotExist
	}
	return &readDirErrorFile{}, nil
}

type readDirErrorFile struct{}

func (*readDirErrorFile) Stat() (fs.FileInfo, error) { return directoryInfo{}, nil }
func (*readDirErrorFile) Read([]byte) (int, error)   { return 0, io.EOF }
func (*readDirErrorFile) Close() error               { return nil }
func (*readDirErrorFile) ReadDir(int) ([]fs.DirEntry, error) {
	return nil, errors.New("fixture read directory")
}

type directoryInfo struct{}

func (directoryInfo) Name() string       { return "." }
func (directoryInfo) Size() int64        { return 0 }
func (directoryInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o555 }
func (directoryInfo) ModTime() time.Time { return time.Time{} }
func (directoryInfo) IsDir() bool        { return true }
func (directoryInfo) Sys() any           { return nil }

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
