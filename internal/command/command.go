// Package command implements the github-ci command-line interface.
package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing/fstest"
	"time"
	"unicode"

	"github.com/gomaja/github-ci/internal/applicability"
	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/evidence"
	"github.com/gomaja/github-ci/internal/exceptions"
	"github.com/gomaja/github-ci/internal/gate"
	"github.com/gomaja/github-ci/internal/generate"
	releaseevidence "github.com/gomaja/github-ci/internal/release"
	"github.com/gomaja/github-ci/internal/reports"
	"github.com/gomaja/github-ci/internal/securefs"
)

const (
	exitSuccess  = 0
	exitFinding  = 1
	exitError    = 2
	maxJSON      = 64 << 20
	flagConfig   = "--config"
	flagManifest = "--manifest"
	flagOutput   = "--output"
	flagPlan     = "--plan"
	flagTool     = "--tool"
)

// Run executes one command with explicit process dependencies.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, now func() time.Time) int {
	dependencies := normalizeDependencies(stdin, stdout, stderr, now)
	if ctx == nil {
		writeError(dependencies.stderr, errors.New("context must not be nil"))
		return exitError
	}
	if err := ctx.Err(); err != nil {
		writeError(dependencies.stderr, err)
		return exitError
	}
	if len(args) == 0 {
		writeError(dependencies.stderr, errors.New("usage: github-ci <preflight|modules|files|applicable|aggregate|parse|record|gate|generate|verify-generated|release-evidence|verify-release-evidence>"))
		return exitError
	}
	return dispatch(ctx, args, dependencies)
}

type runtimeDependencies struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	now    func() time.Time
}

func normalizeDependencies(stdin io.Reader, stdout, stderr io.Writer, now func() time.Time) runtimeDependencies {
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if now == nil {
		now = time.Now
	}
	return runtimeDependencies{stdin: stdin, stdout: stdout, stderr: stderr, now: now}
}

func dispatch(ctx context.Context, args []string, dependencies runtimeDependencies) int {
	switch args[0] {
	case "preflight":
		return runPreflight(ctx, args[1:], dependencies.stderr)
	case "modules":
		return runModules(ctx, args[1:], dependencies.stdout, dependencies.stderr)
	case "files":
		return runFiles(ctx, args[1:], dependencies.stdout, dependencies.stderr)
	case "applicable":
		return runApplicable(args[1:], dependencies.stderr)
	case "aggregate":
		return runAggregate(args[1:], dependencies.stderr)
	case "parse":
		return runParse(args[1:], dependencies.stdin, dependencies.stdout, dependencies.stderr)
	case "record":
		return runRecord(args[1:], dependencies.stderr)
	case "gate":
		return runGate(ctx, args[1:], dependencies.stdout, dependencies.stderr, dependencies.now)
	case "generate":
		return runGenerate(ctx, args[1:], dependencies.stderr, false)
	case "verify-generated":
		return runGenerate(ctx, args[1:], dependencies.stderr, true)
	case "release-evidence":
		return runReleaseEvidence(args[1:], dependencies.stderr)
	case "verify-release-evidence":
		return runVerifyReleaseEvidence(args[1:], dependencies.stderr)
	default:
		writeError(dependencies.stderr, fmt.Errorf("unknown command %q", args[0]))
		return exitError
	}
}

func runReleaseEvidence(args []string, stderr io.Writer) int {
	flags := newFlagSet("release-evidence", stderr)
	root := flags.String("root", ".", "repository root")
	subject := flags.String("subject-sha", "", "release commit SHA")
	sourceDate := flags.String("source-date", "", "release source date in RFC3339")
	manifest := flags.String("manifest", "", "release manifest output")
	checksums := flags.String("checksums", "", "SHA256SUMS output")
	var assets repeatedFlag
	flags.Var(&assets, "asset", "repository-relative release asset (repeatable)")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := requireFlags(flagValue{"--subject-sha", *subject}, flagValue{"--source-date", *sourceDate}, flagValue{flagManifest, *manifest}, flagValue{"--checksums", *checksums}); err != nil {
		writeError(stderr, err)
		return exitError
	}
	parsedDate, err := time.Parse(time.RFC3339, *sourceDate)
	if err != nil {
		writeError(stderr, fmt.Errorf("parse --source-date: %w", err))
		return exitError
	}
	if err := releaseevidence.WriteEvidence(releaseevidence.Input{
		Root: *root, SubjectSHA: *subject, SourceDate: parsedDate, Assets: slices.Clone(assets),
	}, *manifest, *checksums); err != nil {
		writeError(stderr, err)
		return exitError
	}
	return exitSuccess
}

func runVerifyReleaseEvidence(args []string, stderr io.Writer) int {
	flags := newFlagSet("verify-release-evidence", stderr)
	root := flags.String("root", ".", "repository root")
	manifest := flags.String("manifest", "", "release manifest path")
	checksums := flags.String("checksums", "", "SHA256SUMS path")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := requireFlags(flagValue{flagManifest, *manifest}, flagValue{"--checksums", *checksums}); err != nil {
		writeError(stderr, err)
		return exitError
	}
	if err := releaseevidence.Verify(*root, *manifest, *checksums); err != nil {
		writeError(stderr, err)
		return exitError
	}
	return exitSuccess
}

func runFiles(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("files", stderr)
	repository := flags.String("repository", ".", "consumer repository root")
	configPath := flags.String("config", "", "consumer configuration path")
	kind := flags.String("kind", "", "tracked file class")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := requireFlags(flagValue{flagConfig, *configPath}, flagValue{"--kind", *kind}); err != nil {
		writeError(stderr, err)
		return exitError
	}
	if !slices.Contains([]string{"go", "all-go", "shell", "docker", "workflow", "terraform", "markdown", "yaml", "json"}, *kind) {
		writeError(stderr, fmt.Errorf("unsupported file kind %q", *kind))
		return exitError
	}
	tracked, _, err := trackedRepository(ctx, *repository)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	consumer, err := readTrackedConsumer(tracked, *configPath)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	var names []string
	err = fs.WalkDir(tracked, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		matches, matchErr := trackedFileMatches(tracked, name, entry, *kind)
		if matchErr != nil {
			return matchErr
		}
		if !matches {
			return nil
		}
		if *kind == "go" && generatedPath(name, consumer.Generated) {
			return nil
		}
		names = append(names, name)
		return nil
	})
	if err != nil {
		writeError(stderr, fmt.Errorf("list tracked files: %w", err))
		return exitError
	}
	slices.Sort(names)
	for _, name := range names {
		if _, err := io.WriteString(stdout, name+"\x00"); err != nil {
			writeError(stderr, fmt.Errorf("write tracked file list: %w", err))
			return exitError
		}
	}
	return exitSuccess
}

func trackedFileMatches(tracked fs.FS, name string, entry fs.DirEntry, kind string) (bool, error) {
	base := filepath.Base(name)
	lowerBase := strings.ToLower(base)
	extension := strings.ToLower(filepath.Ext(base))
	switch kind {
	case "go", "all-go":
		return extension == ".go", nil
	case "docker":
		return lowerBase == "dockerfile" || lowerBase == "containerfile" ||
			strings.HasPrefix(lowerBase, "dockerfile.") || strings.HasPrefix(lowerBase, "containerfile.") ||
			strings.HasSuffix(lowerBase, ".dockerfile") || strings.HasSuffix(lowerBase, ".containerfile"), nil
	case "workflow":
		return strings.HasPrefix(name, ".github/workflows/") && (extension == ".yml" || extension == ".yaml"), nil
	case "terraform":
		return extension == ".tf", nil
	case "markdown":
		return extension == ".md" || extension == ".markdown", nil
	case "yaml":
		return extension == ".yml" || extension == ".yaml", nil
	case "json":
		return extension == ".json", nil
	case "shell":
		return trackedShellFileMatches(tracked, name, entry, extension)
	default:
		return false, fmt.Errorf("unsupported file kind %q", kind)
	}
}

func trackedShellFileMatches(tracked fs.FS, name string, entry fs.DirEntry, extension string) (bool, error) {
	if slices.Contains([]string{".sh", ".bash", ".bats", ".zsh", ".ksh"}, extension) {
		return true, nil
	}
	info, err := entry.Info()
	if err != nil {
		return false, fmt.Errorf("stat tracked path %q: %w", name, err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return false, nil
	}
	data, err := fs.ReadFile(tracked, name)
	if err != nil {
		return false, fmt.Errorf("read tracked path %q: %w", name, err)
	}
	line, _, _ := bytes.Cut(data, []byte("\n"))
	shebangs := []string{"#!/bin/sh", "#!/bin/bash", "#!/bin/zsh", "#!/bin/ksh", "#!/usr/bin/env sh", "#!/usr/bin/env bash", "#!/usr/bin/env zsh", "#!/usr/bin/env ksh"}
	return slices.ContainsFunc(shebangs, func(prefix string) bool { return bytes.HasPrefix(line, []byte(prefix)) }), nil
}

func runModules(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("modules", stderr)
	repository := flags.String("repository", ".", "consumer repository root")
	configPath := flags.String("config", "", "consumer configuration path")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := requireFlags(flagValue{flagConfig, *configPath}); err != nil {
		writeError(stderr, err)
		return exitError
	}
	tracked, _, err := trackedRepository(ctx, *repository)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	consumer, err := readTrackedConsumer(tracked, *configPath)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	modules, err := consumerModules(tracked, consumer)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	if err := writeJSON(stdout, struct {
		Modules []string `json:"modules"`
	}{Modules: modules}); err != nil {
		writeError(stderr, err)
		return exitError
	}
	return exitSuccess
}

func runApplicable(args []string, stderr io.Writer) int {
	flags := newFlagSet("applicable", stderr)
	planPath := flags.String("plan", "", "applicability plan path")
	tool := flags.String("tool", "", "tool identity")
	commandID := flags.String("command-id", "", "command identity")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := requireFlags(flagValue{flagPlan, *planPath}, flagValue{flagTool, *tool}, flagValue{"--command-id", *commandID}); err != nil {
		writeError(stderr, err)
		return exitError
	}
	plan, err := readPlan(*planPath)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	expected, found := expectedByIdentity(plan, *tool, *commandID)
	if !found {
		writeError(stderr, fmt.Errorf("plan does not expect %s/%s", *tool, *commandID))
		return exitError
	}
	if expected.Applicability == evidence.NotApplicable {
		return exitFinding
	}
	return exitSuccess
}

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }

func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func runAggregate(args []string, stderr io.Writer) int {
	flags := newFlagSet("aggregate", stderr)
	tool := flags.String("tool", "", "native report parser")
	output := flags.String("output", "", "aggregate report path")
	var reportFlags repeatedFlag
	flags.Var(&reportFlags, "report", "module=path native report (repeatable)")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := requireFlags(flagValue{flagTool, *tool}, flagValue{flagOutput, *output}); err != nil {
		writeError(stderr, err)
		return exitError
	}
	named := make([]reports.NamedReport, 0, len(reportFlags))
	for index, value := range reportFlags {
		module, name, found := strings.Cut(value, "=")
		if !found || module == "" || name == "" {
			writeError(stderr, fmt.Errorf("--report %d must use module=path", index))
			return exitError
		}
		data, err := securefs.ReadFile(name)
		if err != nil {
			writeError(stderr, fmt.Errorf("read report %d: %w", index, err))
			return exitError
		}
		named = append(named, reports.NamedReport{Module: module, Data: data})
	}
	var aggregate bytes.Buffer
	if err := reports.WriteAggregate(*tool, named, &aggregate); err != nil {
		writeError(stderr, err)
		return exitError
	}
	if err := writeBytesAtomic(*output, aggregate.Bytes()); err != nil {
		writeError(stderr, err)
		return exitError
	}
	return exitSuccess
}

func runParse(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := newFlagSet("parse", stderr)
	tool := flags.String("tool", "", "native report parser")
	reportPath := flags.String("report", "", "native report path or -")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := noArguments(flags); err != nil {
		writeError(stderr, err)
		return exitError
	}
	if *tool == "" {
		writeError(stderr, errors.New("--tool is required"))
		return exitError
	}
	if *reportPath == "" {
		writeError(stderr, errors.New("--report is required"))
		return exitError
	}
	if !reports.IsSupported(*tool) {
		writeError(stderr, fmt.Errorf("unsupported report tool %q", *tool))
		return exitError
	}
	reader, closeReader, err := openInput(*reportPath, stdin)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	result, parseErr := reports.Count(*tool, reader)
	closeErr := closeReader()
	if parseErr != nil {
		writeError(stderr, parseErr)
		return exitError
	}
	if closeErr != nil {
		writeError(stderr, fmt.Errorf("close report: %w", closeErr))
		return exitError
	}
	if err := writeJSON(stdout, result); err != nil {
		writeError(stderr, err)
		return exitError
	}
	if result.Findings != 0 {
		return exitFinding
	}
	return exitSuccess
}

func runGenerate(ctx context.Context, args []string, stderr io.Writer, verify bool) int {
	flags := newFlagSet("generate", stderr)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := noArguments(flags); err != nil {
		writeError(stderr, err)
		return exitError
	}
	if err := ctx.Err(); err != nil {
		writeError(stderr, err)
		return exitError
	}
	var err error
	if verify {
		err = generate.Verify(*root)
	} else {
		err = generate.Generate(*root)
	}
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	return exitSuccess
}

func runPreflight(ctx context.Context, args []string, stderr io.Writer) int {
	flags := newFlagSet("preflight", stderr)
	repository := flags.String("repository", ".", "consumer repository root")
	configPath := flags.String("config", "", "consumer configuration path")
	policyPath := flags.String("policy", "", "tool policy path")
	profile := flags.String("profile", "", "expected assurance profile")
	subject := flags.String("subject-sha", "", "expected checkout commit")
	output := flags.String("output", "", "applicability plan path")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := requireFlags(
		flagValue{flagConfig, *configPath}, flagValue{"--policy", *policyPath}, flagValue{flagOutput, *output},
	); err != nil {
		writeError(stderr, err)
		return exitError
	}
	plan, err := detectCurrent(ctx, *repository, *configPath, *policyPath, *subject, *profile)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	if err := writeJSONAtomic(*output, plan); err != nil {
		writeError(stderr, err)
		return exitError
	}
	return exitSuccess
}

func runRecord(args []string, stderr io.Writer) int {
	flags := newFlagSet("record", stderr)
	planPath := flags.String("plan", "", "applicability plan path")
	tool := flags.String("tool", "", "tool identity")
	commandID := flags.String("command-id", "", "command identity")
	toolVersion := flags.String("tool-version", "", "observed tool version")
	parserTool := flags.String("parser-tool", "", "native report parser")
	reportPath := flags.String("report", "", "native report path")
	exitCode := flags.Int("exit-code", 0, "producer exit code")
	suppressed := flags.Int("suppressed-count", 0, "observed suppression count")
	output := flags.String("output", "", "evidence record path")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := requireFlags(
		flagValue{flagPlan, *planPath}, flagValue{flagTool, *tool}, flagValue{"--command-id", *commandID},
		flagValue{"--tool-version", *toolVersion}, flagValue{flagOutput, *output},
	); err != nil {
		writeError(stderr, err)
		return exitError
	}
	if *exitCode < 0 || *suppressed < 0 {
		writeError(stderr, errors.New("exit and suppression counts must not be negative"))
		return exitError
	}
	plan, err := readPlan(*planPath)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	record, err := buildRecord(plan, recordOptions{
		tool: *tool, commandID: *commandID, toolVersion: *toolVersion,
		parserTool: *parserTool, reportPath: *reportPath,
		exitCode: *exitCode, suppressed: *suppressed,
	})
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		writeError(stderr, fmt.Errorf("create evidence directory: %w", err))
		return exitError
	}
	if err := evidence.WriteAtomic(*output, record); err != nil {
		writeError(stderr, err)
		return exitError
	}
	if record.Outcome == evidence.OutcomeFail {
		return exitFinding
	}
	return exitSuccess
}

type recordOptions struct {
	tool        string
	commandID   string
	toolVersion string
	parserTool  string
	reportPath  string
	exitCode    int
	suppressed  int
}

func buildRecord(plan evidence.Plan, options recordOptions) (evidence.Record, error) {
	expected, found := expectedByIdentity(plan, options.tool, options.commandID)
	if !found {
		return evidence.Record{}, fmt.Errorf("plan does not expect %s/%s", options.tool, options.commandID)
	}
	record := evidence.Record{
		SchemaVersion: evidence.SchemaVersion, Tool: options.tool, ToolVersion: options.toolVersion,
		PolicyVersion: plan.PolicySHA256, SubjectSHA: plan.SubjectSHA,
		Applicability: expected.Applicability, CommandID: options.commandID,
	}
	if expected.Applicability == evidence.NotApplicable {
		if options.reportPath != "" || options.parserTool != "" || options.exitCode != 0 || options.suppressed != 0 {
			return evidence.Record{}, errors.New("not-applicable evidence must not carry a report, parser, nonzero exit, or suppression")
		}
		record.Outcome = evidence.OutcomeNotApplicable
		return record, nil
	}
	return buildApplicableRecord(record, expected, options)
}

func buildApplicableRecord(record evidence.Record, expected evidence.Expected, options recordOptions) (evidence.Record, error) {
	if options.reportPath == "" {
		return evidence.Record{}, errors.New("applicable evidence requires --report")
	}
	requiredParser, known := reports.ParserTool(expected.ParserVersion)
	if !known {
		return evidence.Record{}, fmt.Errorf("plan parser %q has no native implementation", expected.ParserVersion)
	}
	if options.parserTool != "" && options.parserTool != requiredParser {
		return evidence.Record{}, fmt.Errorf("--parser-tool must be %q for %s", requiredParser, expected.Identity())
	}
	data, err := securefs.ReadFile(options.reportPath)
	if err != nil {
		return evidence.Record{}, fmt.Errorf("read native report: %w", err)
	}
	parsed, err := reports.Count(requiredParser, bytes.NewReader(data))
	if err != nil {
		return evidence.Record{}, err
	}
	record.ExitCode = options.exitCode
	record.FindingCount = parsed.Findings
	record.Suppressed = options.suppressed
	record.ReportSHA256 = digest(data)
	record.Outcome = evidence.OutcomePass
	if options.exitCode != 0 || parsed.Findings != 0 || options.suppressed != 0 {
		record.Outcome = evidence.OutcomeFail
	}
	return record, nil
}

type gateManifest struct {
	SchemaVersion string         `json:"schema_version"`
	Producers     []producerWire `json:"producers"`
}

type producerWire struct {
	Tool          string              `json:"tool"`
	CommandID     string              `json:"command_id"`
	Execution     gate.ExecutionState `json:"execution"`
	RecordPath    string              `json:"record_path,omitempty"`
	ReportPath    string              `json:"report_path,omitempty"`
	ParserTool    string              `json:"parser_tool,omitempty"`
	ParserVersion string              `json:"parser_version,omitempty"`
}

func runGate(ctx context.Context, args []string, stdout, stderr io.Writer, now func() time.Time) int {
	flags := newFlagSet("gate", stderr)
	repository := flags.String("repository", ".", "consumer repository root")
	configPath := flags.String("config", "", "consumer configuration path")
	policyPath := flags.String("policy", "", "tool policy path")
	planPath := flags.String("plan", "", "applicability plan path")
	manifestPath := flags.String("manifest", "", "producer manifest path")
	exceptionsPath := flags.String("exceptions", "", "exception manifest path")
	output := flags.String("output", "", "gate result path")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if err := requireFlags(
		flagValue{flagConfig, *configPath}, flagValue{"--policy", *policyPath},
		flagValue{flagPlan, *planPath}, flagValue{flagManifest, *manifestPath},
	); err != nil {
		writeError(stderr, err)
		return exitError
	}
	plan, err := readPlan(*planPath)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	current, err := detectCurrent(ctx, *repository, *configPath, *policyPath, "", "")
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	manifest, err := readGateManifest(*manifestPath)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	evaluationTime := now().UTC()
	set, exceptionIssues, err := loadGateExceptions(ctx, *repository, *configPath, *exceptionsPath, evaluationTime)
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	planDigest, err := plan.Digest()
	if err != nil {
		writeError(stderr, err)
		return exitError
	}
	input := gate.Input{
		Plan: plan, Exceptions: set, ExceptionIssues: exceptionIssues,
		ObservedSubjectSHA: current.SubjectSHA, ObservedTreeSHA256: current.TreeSHA256,
		ObservedPolicySHA256: current.PolicySHA256, ObservedPlanSHA256: planDigest,
		EvaluationDate: evaluationTime.Format(time.DateOnly),
	}
	records, contexts, assemblyFindings := assembleProducers(plan, current, planDigest, filepath.Dir(*manifestPath), manifest.Producers)
	input.Records = records
	input.Context = contexts
	result := gate.Evaluate(input)
	result.Findings = append(result.Findings, assemblyFindings...)
	slices.SortFunc(result.Findings, func(left, right gate.Finding) int {
		return strings.Compare(left.Tool+"\x00"+left.CommandID+"\x00"+left.Code+"\x00"+left.Detail, right.Tool+"\x00"+right.CommandID+"\x00"+right.Code+"\x00"+right.Detail)
	})
	result.Pass = len(result.Findings) == 0
	if *output != "" {
		if err := writeJSONAtomic(*output, result); err != nil {
			writeError(stderr, err)
			return exitError
		}
	} else if err := writeJSON(stdout, result); err != nil {
		writeError(stderr, err)
		return exitError
	}
	if !result.Pass {
		return exitFinding
	}
	return exitSuccess
}

func loadGateExceptions(ctx context.Context, repository, configPath, configuredPath string, now time.Time) (exceptions.Set, []exceptions.Issue, error) {
	resolvedPath := configuredPath
	if resolvedPath == "" {
		tracked, _, err := trackedRepository(ctx, repository)
		if err != nil {
			return exceptions.Set{}, nil, err
		}
		consumer, err := readTrackedConsumer(tracked, configPath)
		if err != nil {
			return exceptions.Set{}, nil, err
		}
		if consumer.Exceptions != "" {
			resolvedPath = filepath.Join(repository, filepath.FromSlash(consumer.Exceptions))
		}
	}
	if resolvedPath == "" {
		return exceptions.Set{}, nil, nil
	}
	file, err := securefs.Open(resolvedPath)
	if err != nil {
		return exceptions.Set{}, nil, fmt.Errorf("open exceptions: %w", err)
	}
	set, issues, loadErr := exceptions.LoadDetailed(file, now)
	closeErr := file.Close()
	if loadErr != nil {
		return exceptions.Set{}, nil, loadErr
	}
	if closeErr != nil {
		return exceptions.Set{}, nil, fmt.Errorf("close exceptions: %w", closeErr)
	}
	return set, issues, nil
}

func assembleProducers(plan, current evidence.Plan, planDigest, directory string, producers []producerWire) ([]evidence.Record, []gate.RecordContext, []gate.Finding) {
	records := make([]evidence.Record, 0, len(producers))
	contexts := make([]gate.RecordContext, 0, len(producers))
	findings := make([]gate.Finding, 0)
	for _, producer := range producers {
		expected, expectedKnown := expectedByIdentity(plan, producer.Tool, producer.CommandID)
		contextRecord := gate.RecordContext{
			Tool: producer.Tool, CommandID: producer.CommandID,
			SubjectSHA: current.SubjectSHA, PlanSHA256: planDigest,
			TreeSHA256: current.TreeSHA256, DetectorVersion: current.DetectorVersion,
			PolicySHA256: current.PolicySHA256, Execution: producer.Execution,
		}
		if producer.RecordPath != "" {
			record, finding := readProducerRecord(directory, producer)
			if finding != nil {
				findings = append(findings, *finding)
			} else {
				records = append(records, record)
			}
		}
		if producer.ReportPath != "" {
			report, observations, finding := observeProducerReport(directory, producer, expected, expectedKnown)
			contextRecord.Report = report
			contextRecord.Observations = observations
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
		contexts = append(contexts, contextRecord)
	}
	return records, contexts, findings
}

func readProducerRecord(directory string, producer producerWire) (evidence.Record, *gate.Finding) {
	file, err := securefs.OpenInRoot(directory, filepath.FromSlash(producer.RecordPath))
	if err != nil {
		finding := producerFinding(producer, "unreadable-record", "evidence record is unavailable")
		return evidence.Record{}, &finding
	}
	record, readErr := evidence.Read(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		finding := producerFinding(producer, "malformed-record", "evidence record could not be validated")
		return evidence.Record{}, &finding
	}
	return record, nil
}

func observeProducerReport(directory string, producer producerWire, expected evidence.Expected, expectedKnown bool) (*gate.ReportEvidence, []gate.Observation, *gate.Finding) {
	data, err := securefs.ReadFileInRoot(directory, filepath.FromSlash(producer.ReportPath))
	if err != nil {
		finding := producerFinding(producer, "unreadable-report", "native report is unavailable")
		return nil, nil, &finding
	}
	if !expectedKnown {
		finding := producerFinding(producer, "unexpected-report", "producer is not present in the plan")
		return nil, nil, &finding
	}
	parserTool, known := reports.ParserTool(expected.ParserVersion)
	if !known {
		finding := producerFinding(producer, "unsupported-parser", expected.ParserVersion)
		return nil, nil, &finding
	}
	if producer.ParserTool != "" && producer.ParserTool != parserTool {
		finding := producerFinding(producer, "parser-mismatch", "producer parser does not match the plan")
		return nil, nil, &finding
	}
	parsed, err := reports.Count(parserTool, bytes.NewReader(data))
	if err != nil {
		finding := producerFinding(producer, "malformed-report", "native report could not be parsed")
		return nil, nil, &finding
	}
	reportDigest := digest(data)
	observations := make([]gate.Observation, 0, parsed.Findings)
	for index := range parsed.Findings {
		observations = append(observations, gate.Observation{
			Tool: producer.Tool, CommandID: producer.CommandID, Rule: "native-report-finding",
			Fingerprint: fmt.Sprintf("%s:%d", reportDigest, index), Scope: producer.ReportPath,
			Source: gate.SourceAnalyzer,
		})
	}
	return &gate.ReportEvidence{SHA256: reportDigest, ParserVersion: expected.ParserVersion}, observations, nil
}

func producerFinding(producer producerWire, code, detail string) gate.Finding {
	return gate.Finding{Tool: producer.Tool, CommandID: producer.CommandID, Code: code, Detail: detail}
}

func detectCurrent(ctx context.Context, repository, configPath, policyPath, expectedSubject, expectedProfile string) (evidence.Plan, error) {
	if !fs.ValidPath(filepath.ToSlash(configPath)) || hasControl(configPath) {
		return evidence.Plan{}, errors.New("consumer configuration must be a safe repository-relative path")
	}
	tracked, subject, err := trackedRepository(ctx, repository)
	if err != nil {
		return evidence.Plan{}, err
	}
	if expectedSubject != "" && expectedSubject != subject {
		return evidence.Plan{}, errors.New("expected subject does not match checked-out commit")
	}
	consumer, err := readTrackedConsumer(tracked, configPath)
	if err != nil {
		return evidence.Plan{}, err
	}
	if expectedProfile != "" && string(consumer.Profile) != expectedProfile {
		return evidence.Plan{}, fmt.Errorf("configured profile %q does not match requested profile %q", consumer.Profile, expectedProfile)
	}
	policy, err := securefs.ReadFile(policyPath)
	if err != nil {
		return evidence.Plan{}, fmt.Errorf("read tool policy: %w", err)
	}
	if _, err := generate.LoadPolicy(bytes.NewReader(policy)); err != nil {
		return evidence.Plan{}, fmt.Errorf("validate tool policy: %w", err)
	}
	return applicability.Detect(tracked, applicability.Input{
		Consumer: consumer, SubjectSHA: subject, PolicySHA256: digest(policy), Catalog: applicability.DefaultCatalog(),
	})
}

func trackedRepository(ctx context.Context, root string) (fs.FS, string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, "", fmt.Errorf("resolve repository root: %w", err)
	}
	subjectCommand := exec.CommandContext(ctx, "git", "rev-parse", "--verify", "HEAD^{commit}")
	subjectCommand.Dir = root
	subjectBytes, err := subjectCommand.Output()
	if err != nil {
		return nil, "", errors.New("resolve checked-out commit")
	}
	subject := strings.TrimSpace(string(subjectBytes))
	indexCommand := exec.CommandContext(ctx, "git", "ls-files", "--stage", "-z")
	indexCommand.Dir = root
	index, err := indexCommand.Output()
	if err != nil {
		return nil, "", errors.New("enumerate tracked files")
	}
	tracked := make(fstest.MapFS)
	for raw := range bytes.SplitSeq(index, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		before, after, ok := bytes.Cut(raw, []byte{'\t'})
		if !ok {
			return nil, "", errors.New("invalid git index record")
		}
		metadata := strings.Fields(string(before))
		name := string(after)
		if len(metadata) != 3 || metadata[2] != "0" {
			return nil, "", errors.New("git index contains an unmerged entry")
		}
		if metadata[0] != "100644" && metadata[0] != "100755" {
			return nil, "", fmt.Errorf("tracked path %q has unsupported git mode %s", name, metadata[0])
		}
		if !fs.ValidPath(name) || hasControl(name) {
			return nil, "", errors.New("git index contains an unsafe path")
		}
		data, readErr := securefs.ReadFileInRoot(root, filepath.FromSlash(name))
		if readErr != nil {
			return nil, "", fmt.Errorf("read tracked path %q: %w", name, readErr)
		}
		mode := fs.FileMode(0o444)
		if metadata[0] == "100755" {
			mode = 0o555
		}
		tracked[name] = &fstest.MapFile{Data: data, Mode: mode}
	}
	return tracked, subject, nil
}

func readTrackedConsumer(tracked fs.FS, configPath string) (config.Consumer, error) {
	if !fs.ValidPath(filepath.ToSlash(configPath)) || hasControl(configPath) {
		return config.Consumer{}, errors.New("consumer configuration must be a safe repository-relative path")
	}
	configuration, err := tracked.Open(filepath.ToSlash(configPath))
	if err != nil {
		return config.Consumer{}, fmt.Errorf("open tracked consumer configuration: %w", err)
	}
	consumer, decodeErr := config.DecodeConsumer(configuration)
	closeErr := configuration.Close()
	if decodeErr != nil {
		return config.Consumer{}, fmt.Errorf("decode consumer configuration: %w", decodeErr)
	}
	if closeErr != nil {
		return config.Consumer{}, fmt.Errorf("close consumer configuration: %w", closeErr)
	}
	return consumer, nil
}

func consumerModules(tracked fs.FS, consumer config.Consumer) ([]string, error) {
	detected := make([]string, 0)
	err := fs.WalkDir(tracked, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && filepath.Base(name) == "go.mod" {
			module := filepath.ToSlash(filepath.Dir(name))
			if module == "." {
				module = "."
			}
			detected = append(detected, module)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover Go modules: %w", err)
	}
	slices.Sort(detected)
	isGoProfile := consumer.Profile == config.ProfileGoStrict || consumer.Profile == config.ProfileGoLibrary
	if isGoProfile && len(detected) == 0 {
		return nil, fmt.Errorf("profile %q requires a tracked go.mod", consumer.Profile)
	}
	if !isGoProfile && len(detected) != 0 {
		return nil, fmt.Errorf("profile %q would omit tracked Go modules", consumer.Profile)
	}
	if len(consumer.Modules) == 0 {
		return detected, nil
	}
	configured := make([]string, len(consumer.Modules))
	for index, module := range consumer.Modules {
		configured[index] = string(module)
	}
	slices.Sort(configured)
	if !slices.Equal(configured, detected) {
		return nil, errors.New("configured modules do not exactly match tracked go.mod files")
	}
	return configured, nil
}

func generatedPath(name string, generated []string) bool {
	for _, prefix := range generated {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	return false
}

func readPlan(name string) (evidence.Plan, error) {
	var plan evidence.Plan
	if err := readStrictJSONFile(name, &plan); err != nil {
		return evidence.Plan{}, fmt.Errorf("read plan: %w", err)
	}
	if err := evidence.ValidatePlan(plan); err != nil {
		return evidence.Plan{}, fmt.Errorf("validate plan: %w", err)
	}
	return plan, nil
}

func readGateManifest(name string) (gateManifest, error) {
	var manifest gateManifest
	if err := readStrictJSONFile(name, &manifest); err != nil {
		return gateManifest{}, fmt.Errorf("read producer manifest: %w", err)
	}
	if manifest.SchemaVersion != evidence.SchemaVersion {
		return gateManifest{}, fmt.Errorf("producer manifest schema_version must be %q", evidence.SchemaVersion)
	}
	seen := make(map[string]struct{}, len(manifest.Producers))
	for index, producer := range manifest.Producers {
		identity := producer.Tool + "/" + producer.CommandID
		if producer.Tool == "" || producer.CommandID == "" {
			return gateManifest{}, fmt.Errorf("producer %d has an empty identity", index)
		}
		if _, exists := seen[identity]; exists {
			return gateManifest{}, fmt.Errorf("duplicate producer %q", identity)
		}
		seen[identity] = struct{}{}
		if producer.Execution != gate.ExecutionCompleted && producer.Execution != gate.ExecutionFailed && producer.Execution != gate.ExecutionCancelled && producer.Execution != gate.ExecutionTimedOut && producer.Execution != gate.ExecutionSkipped {
			return gateManifest{}, fmt.Errorf("producer %q has invalid execution %q", identity, producer.Execution)
		}
		for _, path := range []flagValue{{"record_path", producer.RecordPath}, {"report_path", producer.ReportPath}} {
			if path.value != "" && (!fs.ValidPath(path.value) || hasControl(path.value)) {
				return gateManifest{}, fmt.Errorf("producer %q has unsafe %s", identity, path.name)
			}
		}
	}
	return manifest, nil
}

func readStrictJSONFile(name string, destination any) error {
	file, err := securefs.Open(name)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxJSON+1))
	closeErr := file.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(data) > maxJSON {
		return fmt.Errorf("JSON exceeds %d byte limit", maxJSON)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains a trailing value")
		}
		return err
	}
	return nil
}

func expectedByIdentity(plan evidence.Plan, tool, commandID string) (evidence.Expected, bool) {
	for _, expected := range plan.Expected {
		if expected.Tool == tool && expected.CommandID == commandID {
			return expected, true
		}
	}
	return evidence.Expected{}, false
}

func openInput(name string, stdin io.Reader) (io.Reader, func() error, error) {
	if name == "-" {
		return stdin, func() error { return nil }, nil
	}
	file, err := securefs.Open(name)
	if err != nil {
		return nil, nil, fmt.Errorf("open report: %w", err)
	}
	return file, file.Close, nil
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}
	return nil
}

func writeJSONAtomic(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	data = append(data, '\n')
	return writeBytesAtomic(name, data)
}

func writeBytesAtomic(name string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+"-*")
	if err != nil {
		return fmt.Errorf("create output temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temporary.Close()
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("set output mode: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("replace output: %w", err)
	}
	committed = true
	return nil
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {}
	return flags
}

func noArguments(flags *flag.FlagSet) error {
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional argument at index %s", strconv.Itoa(0))
	}
	return nil
}

type flagValue struct {
	name  string
	value string
}

func requireFlags(values ...flagValue) error {
	for _, value := range values {
		if value.value == "" {
			return fmt.Errorf("%s is required", value.name)
		}
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

func hasControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func writeError(writer io.Writer, err error) {
	_, _ = fmt.Fprintf(writer, "github-ci: %s\n", err)
}
