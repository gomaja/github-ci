package command

import (
	"context"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gomaja/github-ci/internal/evidence"
	"github.com/gomaja/github-ci/internal/gate"
)

func TestTrackedShellFileMatchesRequiresExecutablePermission(t *testing.T) {
	tracked := fstest.MapFS{
		"script": &fstest.MapFile{Data: []byte("#!/bin/sh\ntrue\n"), Mode: 0o644},
	}
	entries, err := fs.ReadDir(tracked, ".")
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	matched, err := trackedShellFileMatches(tracked, "script", entries[0], "")
	if err != nil {
		t.Fatalf("trackedShellFileMatches() error = %v", err)
	}
	if matched {
		t.Fatal("trackedShellFileMatches() accepted a non-executable extensionless script")
	}
}

func TestRunAggregateRejectsIncompleteReportBindings(t *testing.T) {
	directory := t.TempDir()
	report := filepath.Join(directory, "report.json")
	mustWrite(t, report, `{"schema_version":"1","execution_successful":true}`)

	for _, binding := range []string{"=" + report, "module="} {
		t.Run(binding, func(t *testing.T) {
			code, _, stderr := runForTest(t, []string{
				"aggregate", "--tool", "command-status", "--report", binding,
				"--output", filepath.Join(directory, "aggregate.json"),
			})
			if code != exitError || !strings.Contains(stderr, "--report 0 must use module=path") {
				t.Fatalf("aggregate code = %d, stderr = %q", code, stderr)
			}
		})
	}
}

func TestRunRecordRejectsEachNegativeCountBeforeReadingPlan(t *testing.T) {
	for _, flag := range []string{"--exit-code", "--suppressed-count"} {
		t.Run(flag, func(t *testing.T) {
			code, _, stderr := runForTest(t, []string{
				"record", "--plan", filepath.Join(t.TempDir(), "missing-plan.json"),
				"--tool", "tool", "--command-id", "tool/command", "--tool-version", "1",
				"--output", filepath.Join(t.TempDir(), "record.json"), flag, "-1",
			})
			if code != exitError || !strings.Contains(stderr, "exit and suppression counts must not be negative") {
				t.Fatalf("record code = %d, stderr = %q", code, stderr)
			}
		})
	}
}

func TestBuildRecordRejectsEachNotApplicablePayload(t *testing.T) {
	plan := evidence.Plan{
		PolicySHA256: testDigest([]byte("policy")),
		SubjectSHA:   "0123456789abcdef0123456789abcdef01234567",
		Expected: []evidence.Expected{{
			Tool: "tool", CommandID: "tool/command", Applicability: evidence.NotApplicable,
		}},
	}
	tests := []struct {
		name   string
		mutate func(*recordOptions)
	}{
		{name: "report", mutate: func(options *recordOptions) { options.reportPath = "report.json" }},
		{name: "parser", mutate: func(options *recordOptions) { options.parserTool = "sarif" }},
		{name: "exit", mutate: func(options *recordOptions) { options.exitCode = 1 }},
		{name: "suppression", mutate: func(options *recordOptions) { options.suppressed = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := recordOptions{tool: "tool", commandID: "tool/command", toolVersion: "1"}
			test.mutate(&options)
			_, err := buildRecord(plan, options)
			if err == nil || err.Error() != "not-applicable evidence must not carry a report, parser, nonzero exit, or suppression" {
				t.Fatalf("buildRecord() error = %v", err)
			}
		})
	}
}

func TestBuildApplicableRecordMarksEveryFindingSignal(t *testing.T) {
	expected := evidence.Expected{
		Tool: "go", CommandID: "go/build", ParserVersion: "command-status/v1", Applicability: evidence.Applicable,
	}
	tests := []struct {
		name       string
		report     string
		exitCode   int
		suppressed int
	}{
		{name: "exit", report: `{"schema_version":"1","execution_successful":true}`, exitCode: 1},
		{name: "finding", report: `{"schema_version":"1","execution_successful":false}`},
		{name: "suppression", report: `{"schema_version":"1","execution_successful":true}`, suppressed: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reportPath := filepath.Join(t.TempDir(), "report.json")
			mustWrite(t, reportPath, test.report)
			record, err := buildApplicableRecord(evidence.Record{}, expected, recordOptions{
				tool: "go", reportPath: reportPath, exitCode: test.exitCode, suppressed: test.suppressed,
			})
			if err != nil {
				t.Fatalf("buildApplicableRecord() error = %v", err)
			}
			if record.Outcome != evidence.OutcomeFail {
				t.Fatalf("buildApplicableRecord() outcome = %q, want %q", record.Outcome, evidence.OutcomeFail)
			}
		})
	}
}

func TestReadProducerRecordReportsMissingAndMalformedInput(t *testing.T) {
	directory := t.TempDir()
	mustWrite(t, filepath.Join(directory, "malformed.json"), "{")
	tests := []struct {
		name string
		path string
		code string
	}{
		{name: "missing", path: "missing.json", code: "unreadable-record"},
		{name: "malformed", path: "malformed.json", code: "malformed-record"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, finding := readProducerRecord(directory, producerWire{
				Tool: "tool", CommandID: "tool/command", RecordPath: test.path,
			})
			if record != (evidence.Record{}) || finding == nil || finding.Code != test.code {
				t.Fatalf("readProducerRecord() = %#v, %#v", record, finding)
			}
		})
	}
}

func TestObserveProducerReportRejectsEveryInvalidBoundary(t *testing.T) {
	directory := t.TempDir()
	mustWrite(t, filepath.Join(directory, "clean.json"), `{"schema_version":"1","execution_successful":true}`)
	mustWrite(t, filepath.Join(directory, "malformed.json"), "{")
	validExpected := evidence.Expected{ParserVersion: "command-status/v1"}
	tests := []struct {
		name          string
		path          string
		expected      evidence.Expected
		expectedKnown bool
		code          string
	}{
		{name: "missing", path: "missing.json", expected: validExpected, expectedKnown: true, code: "unreadable-report"},
		{name: "unexpected", path: "clean.json", expected: validExpected, code: "unexpected-report"},
		{name: "unsupported parser", path: "clean.json", expected: evidence.Expected{ParserVersion: "unknown/v1"}, expectedKnown: true, code: "unsupported-parser"},
		{name: "malformed", path: "malformed.json", expected: validExpected, expectedKnown: true, code: "malformed-report"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, observations, finding := observeProducerReport(directory, producerWire{
				Tool: "go", CommandID: "go/build", ReportPath: test.path,
			}, test.expected, test.expectedKnown)
			if report != nil || observations != nil || finding == nil || finding.Code != test.code {
				t.Fatalf("observeProducerReport() = %#v, %#v, %#v", report, observations, finding)
			}
		})
	}
}

func TestDetectCurrentRejectsUnsafeConfigurationPathBeforeRepositoryAccess(t *testing.T) {
	for _, name := range []string{"/absolute", "control\npath"} {
		t.Run(name, func(t *testing.T) {
			_, err := detectCurrent(context.Background(), filepath.Join(t.TempDir(), "missing"), name, "missing-policy", "", "")
			if err == nil || err.Error() != "consumer configuration must be a safe repository-relative path" {
				t.Fatalf("detectCurrent() error = %v", err)
			}
		})
	}
}

func TestTrackedRepositoryRejectsUnmergedIndex(t *testing.T) {
	root := newRepository(t)
	conflictPath := filepath.Join(root, "conflict.txt")
	mustWrite(t, conflictPath, "conflict\n")
	hash := strings.TrimSpace(runGitMutationTest(t, root, nil, "hash-object", "-w", "conflict.txt"))
	index := strings.NewReader(
		"100644 " + hash + " 1\tconflict.txt\n" +
			"100644 " + hash + " 2\tconflict.txt\n" +
			"100644 " + hash + " 3\tconflict.txt\n",
	)
	runGitMutationTest(t, root, index, "update-index", "--index-info")
	if _, _, err := trackedRepository(context.Background(), root); err == nil || err.Error() != "git index contains an unmerged entry" {
		t.Fatalf("trackedRepository() error = %v", err)
	}
}

func TestTrackedRepositoryRejectsControlCharacterPath(t *testing.T) {
	root := newRepository(t)
	mustWrite(t, filepath.Join(root, "control\npath"), "data\n")
	runGitMutationTest(t, root, nil, "add", ".")
	runGitMutationTest(t, root, nil, "commit", "-m", "test: add control path")
	if _, _, err := trackedRepository(context.Background(), root); err == nil || err.Error() != "git index contains an unsafe path" {
		t.Fatalf("trackedRepository() error = %v", err)
	}
}

func TestTrackedRepositoryAcceptsEmptyIndex(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{
		{"init", "-b", "main"},
		{"config", "user.name", "gomaja"},
		{"config", "user.email", "marwanjdid@gmail.com"},
		{"commit", "--allow-empty", "-m", "test: initialize empty fixture"},
	} {
		runGitMutationTest(t, root, nil, args...)
	}
	tracked, subject, err := trackedRepository(context.Background(), root)
	if err != nil {
		t.Fatalf("trackedRepository() error = %v", err)
	}
	entries, err := fs.ReadDir(tracked, ".")
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 0 || len(subject) != 40 {
		t.Fatalf("trackedRepository() entries = %d, subject = %q", len(entries), subject)
	}
}

func TestReadTrackedConsumerRejectsControlCharacterPath(t *testing.T) {
	name := "control\npath"
	tracked := fstest.MapFS{name: &fstest.MapFile{Data: []byte("schema-version: 1\nprofile: repository-only\n")}}
	if _, err := readTrackedConsumer(tracked, name); err == nil || err.Error() != "consumer configuration must be a safe repository-relative path" {
		t.Fatalf("readTrackedConsumer() error = %v", err)
	}
}

func TestReadGateManifestRejectsPartialIdentityAndUnsafePaths(t *testing.T) {
	tests := []struct {
		name     string
		producer producerWire
		want     string
	}{
		{name: "missing tool", producer: producerWire{CommandID: "tool/command", Execution: gate.ExecutionCompleted}, want: "empty identity"},
		{name: "missing command", producer: producerWire{Tool: "tool", Execution: gate.ExecutionCompleted}, want: "empty identity"},
		{name: "unsafe record path", producer: producerWire{Tool: "tool", CommandID: "tool/command", Execution: gate.ExecutionCompleted, RecordPath: "control\npath"}, want: "unsafe record_path"},
		{name: "unsafe report path", producer: producerWire{Tool: "tool", CommandID: "tool/command", Execution: gate.ExecutionCompleted, ReportPath: "/absolute"}, want: "unsafe report_path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			writeTestJSON(t, path, gateManifest{SchemaVersion: evidence.SchemaVersion, Producers: []producerWire{test.producer}})
			if _, err := readGateManifest(path); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("readGateManifest() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestExpectedByIdentityRequiresBothFields(t *testing.T) {
	plan := evidence.Plan{Expected: []evidence.Expected{
		{Tool: "target", CommandID: "other"},
		{Tool: "other", CommandID: "target/command"},
		{Tool: "target", CommandID: "target/command", ParserVersion: "expected"},
	}}
	got, found := expectedByIdentity(plan, "target", "target/command")
	if !found || got.ParserVersion != "expected" {
		t.Fatalf("expectedByIdentity() = %#v, %t", got, found)
	}
}

func runGitMutationTest(t *testing.T, root string, stdin io.Reader, args ...string) string {
	t.Helper()
	command := exec.CommandContext(t.Context(), "git", args...)
	command.Dir = root
	command.Stdin = stdin
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return string(output)
}
