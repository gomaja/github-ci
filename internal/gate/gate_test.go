package gate

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/github-ci/internal/evidence"
	"github.com/gomaja/github-ci/internal/exceptions"
)

const (
	testSubject = "0123456789abcdef0123456789abcdef01234567"
	testTree    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testPolicy  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testReport  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func TestEvaluatePassesCompleteCleanEvidence(t *testing.T) {
	result := Evaluate(validInput(t))
	if !result.Pass || len(result.Findings) != 0 {
		t.Fatalf("Evaluate() = %#v", result)
	}
}

func TestEvaluateFailsClosedTruthTable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Input)
		code   string
	}{
		{name: "finding", mutate: addOpenFinding, code: "open-finding"},
		{name: "nonzero exit", mutate: func(input *Input) { input.Records[0].Outcome = evidence.OutcomeFail; input.Records[0].ExitCode = 1 }, code: "nonzero-exit"},
		{name: "missing record", mutate: func(input *Input) { input.Records = nil }, code: "missing-record"},
		{name: "duplicate record", mutate: func(input *Input) { input.Records = append(input.Records, input.Records[0]) }, code: "duplicate-record"},
		{name: "malformed record", mutate: func(input *Input) { input.Records[0].SchemaVersion = "2" }, code: "invalid-record"},
		{name: "failed execution", mutate: setExecution(ExecutionFailed), code: "execution-failed"},
		{name: "cancelled execution", mutate: setExecution(ExecutionCancelled), code: "execution-cancelled"},
		{name: "timed out execution", mutate: setExecution(ExecutionTimedOut), code: "execution-timed-out"},
		{name: "unexpected skip", mutate: setExecution(ExecutionSkipped), code: "unexpected-skip"},
		{name: "missing context", mutate: func(input *Input) { input.Context = nil }, code: "missing-context"},
		{name: "report hash mismatch", mutate: func(input *Input) {
			context := onlyContext(*input)
			context.Report.SHA256 = testTree
			setOnlyContext(input, context)
		}, code: "report-hash-mismatch"},
		{name: "parser mismatch", mutate: func(input *Input) {
			context := onlyContext(*input)
			context.Report.ParserVersion = "sarif/v2"
			setOnlyContext(input, context)
		}, code: "parser-mismatch"},
		{name: "policy mismatch", mutate: func(input *Input) { input.Records[0].PolicyVersion = testTree }, code: "policy-mismatch"},
		{name: "subject mismatch", mutate: func(input *Input) { input.Records[0].SubjectSHA = strings.Repeat("a", 40) }, code: "subject-mismatch"},
		{name: "observed tree mismatch", mutate: func(input *Input) { input.ObservedTreeSHA256 = testReport }, code: "tree-mismatch"},
		{name: "observed policy mismatch", mutate: func(input *Input) { input.ObservedPolicySHA256 = testReport }, code: "policy-mismatch"},
		{name: "observed subject mismatch", mutate: func(input *Input) { input.ObservedSubjectSHA = strings.Repeat("b", 40) }, code: "subject-mismatch"},
		{name: "observed plan mismatch", mutate: func(input *Input) { input.ObservedPlanSHA256 = testReport }, code: "plan-mismatch"},
		{name: "context plan mismatch", mutate: func(input *Input) {
			context := onlyContext(*input)
			context.PlanSHA256 = testReport
			setOnlyContext(input, context)
		}, code: "context-plan-mismatch"},
		{name: "context tree mismatch", mutate: func(input *Input) {
			context := onlyContext(*input)
			context.TreeSHA256 = testReport
			setOnlyContext(input, context)
		}, code: "context-tree-mismatch"},
		{name: "context detector mismatch", mutate: func(input *Input) {
			context := onlyContext(*input)
			context.DetectorVersion = "other/v1"
			setOnlyContext(input, context)
		}, code: "context-detector-mismatch"},
		{name: "context policy mismatch", mutate: func(input *Input) {
			context := onlyContext(*input)
			context.PolicySHA256 = testTree
			setOnlyContext(input, context)
		}, code: "context-policy-mismatch"},
		{name: "context subject mismatch", mutate: func(input *Input) {
			context := onlyContext(*input)
			context.SubjectSHA = strings.Repeat("c", 40)
			setOnlyContext(input, context)
		}, code: "context-subject-mismatch"},
		{name: "outcome failure without findings", mutate: func(input *Input) { input.Records[0].Outcome = evidence.OutcomeFail }, code: "failed-outcome"},
		{name: "unexpected record", mutate: func(input *Input) {
			record := input.Records[0]
			record.Tool = "semgrep"
			record.CommandID = "semgrep/source"
			input.Records = append(input.Records, record)
		}, code: "unexpected-record"},
		{name: "unexpected context", mutate: func(input *Input) {
			context := onlyContext(*input)
			context.Tool = "semgrep"
			context.CommandID = "semgrep/source"
			input.Context = append(input.Context, context)
		}, code: "unexpected-context"},
		{name: "duplicate context", mutate: func(input *Input) { input.Context = append(input.Context, input.Context[0]) }, code: "duplicate-context"},
		{name: "exception issue", mutate: func(input *Input) {
			input.ExceptionIssues = []exceptions.Issue{{Index: 0, Code: "expired", Detail: "2026-08-01"}}
		}, code: "exception-expired"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validInput(t)
			test.mutate(&input)
			result := Evaluate(input)
			if result.Pass || !hasFinding(result, test.code) {
				t.Fatalf("Evaluate() = %#v, want code %q", result, test.code)
			}
		})
	}
}

func TestEvaluateRequiresIndependentReportDigest(t *testing.T) {
	input := validInput(t)
	context := onlyContext(input)
	context.Report = nil
	setOnlyContext(&input, context)
	result := Evaluate(input)
	if result.Pass || !hasFinding(result, "missing-report") {
		t.Fatalf("Evaluate() = %#v", result)
	}
}

func TestEvaluatePreservesExecutionFailureWhenRecordIsMissing(t *testing.T) {
	for _, state := range []ExecutionState{ExecutionCancelled, ExecutionTimedOut, ExecutionSkipped} {
		t.Run(string(state), func(t *testing.T) {
			input := validInput(t)
			input.Records = nil
			setExecution(state)(&input)
			result := Evaluate(input)
			if !hasFinding(result, "missing-record") {
				t.Fatalf("Evaluate() = %#v, missing record was not reported", result)
			}
			if state == ExecutionSkipped && !hasFinding(result, "unexpected-skip") {
				t.Fatalf("Evaluate() = %#v, skipped producer was not reported", result)
			}
		})
	}
}

func TestEvaluateAcceptsOnlyDetectorBackedNotApplicable(t *testing.T) {
	input := validNotApplicableInput(t)
	result := Evaluate(input)
	if !result.Pass {
		t.Fatalf("Evaluate() = %#v", result)
	}

	invalid := input
	invalid.Records = slices.Clone(input.Records)
	invalid.Records[0].Applicability = evidence.Applicable
	invalid.Records[0].Outcome = evidence.OutcomePass
	invalid.Records[0].ReportSHA256 = testReport
	result = Evaluate(invalid)
	if result.Pass || !hasFinding(result, "applicability-mismatch") {
		t.Fatalf("Evaluate(invalid N/A) = %#v", result)
	}
}

func TestEvaluateRejectsReasonFromDifferentCommand(t *testing.T) {
	input := validNotApplicableInput(t)
	input.Plan.Expected[0].ReasonCode = "no-dockerfiles"
	digest, err := input.Plan.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	input.ObservedPlanSHA256 = digest
	context := onlyContext(input)
	context.PlanSHA256 = digest
	setOnlyContext(&input, context)
	result := Evaluate(input)
	if result.Pass || !hasFinding(result, "invalid-na-reason") {
		t.Fatalf("Evaluate() = %#v", result)
	}
}

func TestEvaluateConsumesValidExceptionOneToOne(t *testing.T) {
	input := validInput(t)
	addOpenFinding(&input)
	observation := onlyContext(input).Observations[0]
	input.Exceptions = validExceptionSet(t, observation)
	result := Evaluate(input)
	if !result.Pass || len(result.Findings) != 0 {
		t.Fatalf("Evaluate() = %#v", result)
	}
}

func TestEvaluateRejectsObservationAndExceptionMismatches(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Input)
		code   string
	}{
		{name: "missing observations", mutate: func(input *Input) {
			addOpenFinding(input)
			context := onlyContext(*input)
			context.Observations = nil
			setOnlyContext(input, context)
		}, code: "missing-observations"},
		{name: "count mismatch", mutate: func(input *Input) {
			context := onlyContext(*input)
			context.Observations = []Observation{validObservation(false)}
			setOnlyContext(input, context)
		}, code: "observation-count-mismatch"},
		{name: "unmatched inline suppression", mutate: func(input *Input) {
			input.Records[0].Suppressed = 1
			context := onlyContext(*input)
			context.Observations = []Observation{validObservation(true)}
			setOnlyContext(input, context)
		}, code: "unmatched-suppression"},
		{name: "invalid observation source", mutate: func(input *Input) {
			addOpenFinding(input)
			context := onlyContext(*input)
			context.Observations[0].Source = "baseline"
			setOnlyContext(input, context)
		}, code: "invalid-observation"},
		{name: "observation command mismatch", mutate: func(input *Input) {
			addOpenFinding(input)
			context := onlyContext(*input)
			context.Observations[0].CommandID = "staticcheck/other"
			setOnlyContext(input, context)
		}, code: "invalid-observation"},
		{name: "unused exception", mutate: func(input *Input) {
			observation := validObservation(false)
			observation.Fingerprint = "sha256:unused-fingerprint"
			input.Exceptions = validExceptionSet(t, observation)
		}, code: "unused-exception"},
		{name: "exception reused", mutate: func(input *Input) {
			input.Records[0].Outcome = evidence.OutcomeFail
			input.Records[0].FindingCount = 2
			context := onlyContext(*input)
			observation := validObservation(false)
			context.Observations = []Observation{observation, observation}
			setOnlyContext(input, context)
			input.Exceptions = validExceptionSet(t, observation)
		}, code: "exception-reused"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validInput(t)
			test.mutate(&input)
			result := Evaluate(input)
			if result.Pass || !hasFinding(result, test.code) {
				t.Fatalf("Evaluate() = %#v, want %q", result, test.code)
			}
		})
	}
}

func TestEvaluateSortsFindingsDeterministically(t *testing.T) {
	input := validInput(t)
	input.Records = nil
	input.Context = nil
	input.ExceptionIssues = []exceptions.Issue{
		{Index: 2, Code: "expired", Detail: "b"},
		{Index: 1, Code: "invalid", Detail: "a"},
	}
	result := Evaluate(input)
	if slices.IsSortedFunc(result.Findings, compareFinding) == false {
		t.Fatalf("findings are not sorted: %#v", result.Findings)
	}
}

func FuzzEvaluate(f *testing.F) {
	input := validInput(f)
	seed, err := json.Marshal(input)
	if err != nil {
		f.Fatalf("marshal seed: %v", err)
	}
	f.Add(seed)
	f.Add([]byte(`{"plan":{}}`))
	f.Add([]byte(`{"records":[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var candidate Input
		if err := json.Unmarshal(data, &candidate); err != nil {
			return
		}
		_ = Evaluate(candidate)
	})
}

func validInput(t testing.TB) Input {
	t.Helper()
	plan := evidence.Plan{
		SchemaVersion: evidence.SchemaVersion, DetectorVersion: "applicability/v1",
		SubjectSHA: testSubject, TreeSHA256: testTree, PolicySHA256: testPolicy,
		Expected: []evidence.Expected{{
			Tool: "staticcheck", CommandID: "staticcheck/default",
			ParserVersion: "staticcheck-jsonl/v1", Applicability: evidence.Applicable,
		}},
	}
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	record := evidence.Record{
		SchemaVersion: evidence.SchemaVersion, Tool: "staticcheck", ToolVersion: "2026.1",
		PolicyVersion: testPolicy, SubjectSHA: testSubject, Applicability: evidence.Applicable,
		CommandID: "staticcheck/default", ReportSHA256: testReport, Outcome: evidence.OutcomePass,
	}
	return Input{
		Plan: plan, Records: []evidence.Record{record},
		Context: []RecordContext{{
			Tool: "staticcheck", CommandID: "staticcheck/default",
			SubjectSHA: testSubject, PlanSHA256: planDigest, TreeSHA256: testTree,
			DetectorVersion: plan.DetectorVersion, PolicySHA256: testPolicy,
			Execution: ExecutionCompleted,
			Report:    &ReportEvidence{SHA256: testReport, ParserVersion: plan.Expected[0].ParserVersion},
		}},
		ObservedSubjectSHA: testSubject, ObservedTreeSHA256: testTree,
		ObservedPolicySHA256: testPolicy, ObservedPlanSHA256: planDigest,
	}
}

func validNotApplicableInput(t testing.TB) Input {
	t.Helper()
	input := validInput(t)
	input.Plan.Expected[0].Applicability = evidence.NotApplicable
	input.Plan.Expected[0].ReasonCode = "no-go-module"
	digest, err := input.Plan.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	input.ObservedPlanSHA256 = digest
	input.Records[0].Applicability = evidence.NotApplicable
	input.Records[0].Outcome = evidence.OutcomeNotApplicable
	input.Records[0].ReportSHA256 = ""
	context := onlyContext(input)
	context.PlanSHA256 = digest
	context.Execution = ExecutionSkipped
	context.Report = nil
	setOnlyContext(&input, context)
	return input
}

func addOpenFinding(input *Input) {
	input.Records[0].Outcome = evidence.OutcomeFail
	input.Records[0].FindingCount = 1
	context := onlyContext(*input)
	context.Observations = []Observation{validObservation(false)}
	setOnlyContext(input, context)
}

func validObservation(suppressed bool) Observation {
	source := SourceAnalyzer
	if suppressed {
		source = SourceInline
	}
	return Observation{
		Tool: "staticcheck", CommandID: "staticcheck/default", Rule: "SA1000",
		Fingerprint: "sha256:0123456789abcdef", Scope: "internal/parser.go",
		Suppressed: suppressed, Source: source,
	}
}

func setExecution(state ExecutionState) func(*Input) {
	return func(input *Input) {
		context := onlyContext(*input)
		context.Execution = state
		setOnlyContext(input, context)
	}
}

func onlyContext(input Input) RecordContext {
	if len(input.Context) != 0 {
		return input.Context[0]
	}
	return RecordContext{}
}

func setOnlyContext(input *Input, context RecordContext) {
	input.Context = []RecordContext{context}
}

func hasFinding(result Result, code string) bool {
	return slices.ContainsFunc(result.Findings, func(finding Finding) bool { return finding.Code == code })
}

func validExceptionSet(t testing.TB, observation Observation) exceptions.Set {
	t.Helper()
	document := fmt.Sprintf(`schema-version: 1
exceptions:
  - tool: %s
    rule: %s
    fingerprint: %s
    scope: %s
    rationale: Native report evidence proves this exact result is a false positive.
    owner: gomaja
    approval: gomaja/github-ci#12
    created: 2026-08-01
    expires: 2026-08-31
`, observation.Tool, observation.Rule, observation.Fingerprint, observation.Scope)
	set, issues, err := exceptions.LoadDetailed(strings.NewReader(document), time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC))
	if err != nil || len(issues) != 0 {
		t.Fatalf("LoadDetailed() issues = %#v, error = %v", issues, err)
	}
	return set
}
