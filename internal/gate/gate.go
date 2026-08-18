// Package gate evaluates complete assurance evidence without trusting job status alone.
package gate

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/gomaja/github-ci/internal/applicability"
	"github.com/gomaja/github-ci/internal/evidence"
	"github.com/gomaja/github-ci/internal/exceptions"
	"github.com/gomaja/github-ci/internal/pathpolicy"
)

var (
	gitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ExecutionState is the platform-neutral conclusion of an expected producer.
type ExecutionState string

const (
	ExecutionCompleted ExecutionState = "completed"
	ExecutionFailed    ExecutionState = "failed"
	ExecutionCancelled ExecutionState = "cancelled"
	ExecutionTimedOut  ExecutionState = "timed-out"
	ExecutionSkipped   ExecutionState = "skipped"
)

// ObservationSource identifies where a finding or suppression was observed.
type ObservationSource string

const (
	SourceAnalyzer   ObservationSource = "analyzer"
	SourceInline     ObservationSource = "inline"
	SourceIgnoreFile ObservationSource = "ignore-file"
)

// ReportEvidence is an independently observed native report identity.
type ReportEvidence struct {
	SHA256        string `json:"sha256"`
	ParserVersion string `json:"parser_version"`
}

// Observation is one stable finding or suppression identity from a native report.
type Observation struct {
	Tool        string            `json:"tool"`
	CommandID   string            `json:"command_id"`
	Rule        string            `json:"rule"`
	Fingerprint string            `json:"fingerprint"`
	Scope       string            `json:"scope"`
	Suppressed  bool              `json:"suppressed"`
	Source      ObservationSource `json:"source"`
}

// RecordContext independently binds one producer to execution and artifact facts.
type RecordContext struct {
	Tool            string          `json:"tool"`
	CommandID       string          `json:"command_id"`
	SubjectSHA      string          `json:"subject_sha"`
	PlanSHA256      string          `json:"plan_sha256"`
	TreeSHA256      string          `json:"tree_sha256"`
	DetectorVersion string          `json:"detector_version"`
	PolicySHA256    string          `json:"policy_sha256"`
	Execution       ExecutionState  `json:"execution"`
	Report          *ReportEvidence `json:"report,omitempty"`
	Observations    []Observation   `json:"observations,omitempty"`
}

// Identity returns the producer identity carried by this context.
func (context RecordContext) Identity() string { return context.Tool + "/" + context.CommandID }

// Input contains every independently collected fact required by the pure gate.
type Input struct {
	Plan                 evidence.Plan      `json:"plan"`
	Records              []evidence.Record  `json:"records"`
	Context              []RecordContext    `json:"context"`
	Exceptions           exceptions.Set     `json:"exceptions"`
	ExceptionIssues      []exceptions.Issue `json:"exception_issues"`
	ObservedSubjectSHA   string             `json:"observed_subject_sha"`
	ObservedTreeSHA256   string             `json:"observed_tree_sha256"`
	ObservedPolicySHA256 string             `json:"observed_policy_sha256"`
	ObservedPlanSHA256   string             `json:"observed_plan_sha256"`
	EvaluationDate       string             `json:"evaluation_date"`
}

// Finding is one blocking aggregate-gate result.
type Finding struct {
	Tool      string `json:"tool"`
	CommandID string `json:"command_id"`
	Code      string `json:"code"`
	Detail    string `json:"detail"`
}

// Result passes if and only if no findings remain.
type Result struct {
	Pass     bool      `json:"pass"`
	Findings []Finding `json:"findings"`
}

// Evaluate validates all layers of evidence and returns deterministic findings.
func Evaluate(input Input) Result {
	findings := make([]Finding, 0)
	addGlobal := func(code, detail string) {
		findings = append(findings, Finding{Tool: "github-ci", CommandID: "gate/input", Code: code, Detail: detail})
	}

	planValid := true
	if err := evidence.ValidatePlan(input.Plan); err != nil {
		addGlobal("invalid-plan", err.Error())
		planValid = false
	}
	planDigest := ""
	if planValid {
		var err error
		planDigest, err = input.Plan.Digest()
		if err != nil {
			addGlobal("invalid-plan", err.Error())
			planValid = false
		}
	}
	if !gitSHAPattern.MatchString(input.ObservedSubjectSHA) || input.ObservedSubjectSHA != input.Plan.SubjectSHA {
		addGlobal("subject-mismatch", "independently observed subject does not match the plan")
	}
	if !digestPattern.MatchString(input.ObservedTreeSHA256) || input.ObservedTreeSHA256 != input.Plan.TreeSHA256 {
		addGlobal("tree-mismatch", "independently observed tree digest does not match the plan")
	}
	if !digestPattern.MatchString(input.ObservedPolicySHA256) || input.ObservedPolicySHA256 != input.Plan.PolicySHA256 {
		addGlobal("policy-mismatch", "independently observed policy digest does not match the plan")
	}
	if !digestPattern.MatchString(input.ObservedPlanSHA256) || (planValid && input.ObservedPlanSHA256 != planDigest) {
		addGlobal("plan-mismatch", "independently observed plan digest does not match the validated plan")
	}

	for _, issue := range input.ExceptionIssues {
		findings = append(findings, Finding{
			Tool: "exceptions", CommandID: "exceptions/manifest",
			Code:   "exception-" + issue.Code,
			Detail: fmt.Sprintf("entry %d: %s", issue.Index, issue.Detail),
		})
	}
	if validatedOn := input.Exceptions.ValidatedOn(); validatedOn != "" && validatedOn != input.EvaluationDate {
		addGlobal("exception-validation-date-mismatch", fmt.Sprintf("exception set was validated on %q, gate evaluates %q", validatedOn, input.EvaluationDate))
	}
	for _, issue := range input.Exceptions.ValidateOn(input.EvaluationDate) {
		code := "exception-" + issue.Code
		if issue.Code == "invalid-validation-date" {
			code = issue.Code
		}
		findings = append(findings, Finding{
			Tool: "exceptions", CommandID: "exceptions/manifest",
			Code: code, Detail: fmt.Sprintf("entry %d: %s", issue.Index, issue.Detail),
		})
	}

	exceptionEntries := input.Exceptions.Entries()
	exceptionCounts := make(map[string]int, len(exceptionEntries))
	for _, entry := range exceptionEntries {
		exceptionCounts[entry.Identity()]++
	}
	for identity, count := range exceptionCounts {
		if count > 1 {
			findings = append(findings, Finding{Tool: "exceptions", CommandID: "exceptions/manifest", Code: "duplicate-exception", Detail: identity})
		}
	}
	consumedExceptions := make([]bool, len(exceptionEntries))

	recordsByIdentity := make(map[string][]evidence.Record, len(input.Records))
	for index, record := range input.Records {
		identity := record.Identity()
		recordsByIdentity[identity] = append(recordsByIdentity[identity], record)
		if err := evidence.ValidateRecord(record); err != nil {
			findings = append(findings, Finding{Tool: record.Tool, CommandID: record.CommandID, Code: "invalid-record", Detail: fmt.Sprintf("record %d: %s", index, err)})
		}
	}

	expectedIdentities := make(map[string]evidence.Expected, len(input.Plan.Expected))
	if planValid {
		for _, expected := range input.Plan.Expected {
			expectedIdentities[expected.Identity()] = expected
		}
	}
	for identity, records := range recordsByIdentity {
		if _, expected := expectedIdentities[identity]; !expected {
			for _, record := range records {
				findings = append(findings, Finding{Tool: record.Tool, CommandID: record.CommandID, Code: "unexpected-record", Detail: identity})
			}
		}
	}
	contextsByIdentity := make(map[string][]RecordContext, len(input.Context))
	for _, context := range input.Context {
		identity := context.Identity()
		contextsByIdentity[identity] = append(contextsByIdentity[identity], context)
		if _, expected := expectedIdentities[identity]; !expected {
			findings = append(findings, Finding{Tool: context.Tool, CommandID: context.CommandID, Code: "unexpected-context", Detail: identity})
		}
	}

	if planValid {
		for _, expected := range input.Plan.Expected {
			identity := expected.Identity()
			records := recordsByIdentity[identity]
			if len(records) == 0 {
				findings = append(findings, Finding{Tool: expected.Tool, CommandID: expected.CommandID, Code: "missing-record", Detail: identity})
			}
			if len(records) > 1 {
				findings = append(findings, Finding{Tool: expected.Tool, CommandID: expected.CommandID, Code: "duplicate-record", Detail: fmt.Sprintf("%s has %d records", identity, len(records))})
			}

			contexts := contextsByIdentity[identity]
			hasContext := len(contexts) == 1
			context := RecordContext{}
			for _, candidate := range contexts {
				findings = append(findings, validateContext(input, expected, planDigest, candidate)...)
			}
			if len(contexts) == 0 {
				findings = append(findings, Finding{Tool: expected.Tool, CommandID: expected.CommandID, Code: "missing-context", Detail: identity})
			} else if len(contexts) > 1 {
				findings = append(findings, Finding{Tool: expected.Tool, CommandID: expected.CommandID, Code: "duplicate-context", Detail: fmt.Sprintf("%s has %d contexts", identity, len(contexts))})
			} else {
				context = contexts[0]
			}
			if len(records) != 1 {
				continue
			}
			record := records[0]
			findings = append(findings, validateRecordAgainstExpected(input.Plan, expected, record)...)
			if !hasContext {
				continue
			}
			if expected.Applicability == evidence.Applicable && context.Report != nil && record.ReportSHA256 != context.Report.SHA256 {
				findings = append(findings, Finding{
					Tool: expected.Tool, CommandID: expected.CommandID,
					Code: "report-hash-mismatch", Detail: "record report digest does not match independently observed report",
				})
			}
			if expected.Applicability == evidence.NotApplicable {
				wantReason, known := applicability.ReasonFor(expected.Tool, expected.CommandID)
				if !known || expected.ReasonCode != wantReason {
					findings = append(findings, Finding{Tool: expected.Tool, CommandID: expected.CommandID, Code: "invalid-na-reason", Detail: expected.ReasonCode})
				}
				continue
			}
			findings = append(findings, evaluateObservations(expected, record, context.Observations, input.Exceptions, consumedExceptions)...)
		}
	}

	for index, entry := range exceptionEntries {
		if !consumedExceptions[index] {
			findings = append(findings, Finding{Tool: entry.Tool, CommandID: "exceptions/manifest", Code: "unused-exception", Detail: entry.Identity()})
		}
	}

	slices.SortFunc(findings, compareFinding)
	return Result{Pass: len(findings) == 0, Findings: findings}
}

func validateContext(input Input, expected evidence.Expected, planDigest string, context RecordContext) []Finding {
	findings := make([]Finding, 0)
	add := func(code, detail string) {
		findings = append(findings, Finding{Tool: expected.Tool, CommandID: expected.CommandID, Code: code, Detail: detail})
	}
	if context.SubjectSHA != input.ObservedSubjectSHA {
		add("context-subject-mismatch", "producer subject does not match independently observed subject")
	}
	if context.PlanSHA256 != planDigest {
		add("context-plan-mismatch", "producer plan digest does not match validated plan")
	}
	if context.TreeSHA256 != input.ObservedTreeSHA256 {
		add("context-tree-mismatch", "producer tree digest does not match independently observed tree")
	}
	if context.DetectorVersion != input.Plan.DetectorVersion {
		add("context-detector-mismatch", "producer detector version does not match plan")
	}
	if context.PolicySHA256 != input.ObservedPolicySHA256 {
		add("context-policy-mismatch", "producer policy digest does not match independently observed policy")
	}

	if expected.Applicability == evidence.NotApplicable {
		if context.Execution != ExecutionSkipped {
			add(executionCode(context.Execution, false), fmt.Sprintf("not-applicable producer concluded %q", context.Execution))
		}
		if context.Report != nil {
			add("unexpected-report", "not-applicable producer must not have report evidence")
		}
		if len(context.Observations) != 0 {
			add("unexpected-observations", "not-applicable producer must not have observations")
		}
		return findings
	}
	if context.Execution != ExecutionCompleted {
		add(executionCode(context.Execution, true), fmt.Sprintf("applicable producer concluded %q", context.Execution))
	}
	if context.Report == nil {
		add("missing-report", "applicable producer has no independently observed native report")
		return findings
	}
	if !digestPattern.MatchString(context.Report.SHA256) {
		add("invalid-report-hash", "observed report digest is malformed")
	}
	if context.Report.ParserVersion != expected.ParserVersion {
		add("parser-mismatch", fmt.Sprintf("observed parser %q does not match %q", context.Report.ParserVersion, expected.ParserVersion))
	}
	return findings
}

func validateRecordAgainstExpected(plan evidence.Plan, expected evidence.Expected, record evidence.Record) []Finding {
	findings := make([]Finding, 0)
	add := func(code, detail string) {
		findings = append(findings, Finding{Tool: expected.Tool, CommandID: expected.CommandID, Code: code, Detail: detail})
	}
	if record.Tool != expected.Tool || record.CommandID != expected.CommandID {
		add("identity-mismatch", record.Identity())
	}
	if record.SubjectSHA != plan.SubjectSHA {
		add("subject-mismatch", "record subject does not match plan")
	}
	if record.PolicyVersion != plan.PolicySHA256 {
		add("policy-mismatch", "record policy does not match plan")
	}
	if record.Applicability != expected.Applicability {
		add("applicability-mismatch", fmt.Sprintf("record is %q, expected %q", record.Applicability, expected.Applicability))
	}
	if expected.Applicability == evidence.NotApplicable {
		if record.Outcome != evidence.OutcomeNotApplicable || record.ExitCode != 0 || record.FindingCount != 0 || record.Suppressed != 0 || record.ReportSHA256 != "" {
			add("invalid-na-record", "not-applicable record is not detector-backed N/A evidence")
		}
		return findings
	}
	if record.ExitCode != 0 {
		add("nonzero-exit", fmt.Sprintf("producer exit code is %d", record.ExitCode))
	}
	if record.Outcome == evidence.OutcomeNotApplicable {
		add("unexpected-na", "applicable analyzer reported N/A")
	}
	if record.Outcome == evidence.OutcomeFail && record.FindingCount == 0 && record.Suppressed == 0 && record.ExitCode == 0 {
		add("failed-outcome", "producer failed without a typed finding or suppression")
	}
	return findings
}

func evaluateObservations(expected evidence.Expected, record evidence.Record, observations []Observation, set exceptions.Set, consumed []bool) []Finding {
	findings := make([]Finding, 0)
	add := func(code, detail string) {
		findings = append(findings, Finding{Tool: expected.Tool, CommandID: expected.CommandID, Code: code, Detail: detail})
	}
	if (record.FindingCount > 0 || record.Suppressed > 0) && len(observations) == 0 {
		add("missing-observations", "nonzero aggregate counts have no stable observations")
	}
	openCount := 0
	suppressedCount := 0
	for _, observation := range observations {
		if observation.Suppressed {
			suppressedCount++
		} else {
			openCount++
		}
	}
	if openCount != record.FindingCount || suppressedCount != record.Suppressed {
		add("observation-count-mismatch", fmt.Sprintf("observations open=%d suppressed=%d, record open=%d suppressed=%d", openCount, suppressedCount, record.FindingCount, record.Suppressed))
	}

	for index, observation := range observations {
		if err := validateObservation(expected, observation); err != nil {
			add("invalid-observation", fmt.Sprintf("observation %d: %s", index, err))
			continue
		}
		exceptionIndex := set.FindExact(observation.Tool, observation.Rule, observation.Fingerprint, observation.Scope)
		if exceptionIndex < 0 {
			code := "open-finding"
			if observation.Suppressed {
				code = "unmatched-suppression"
			}
			add(code, observationIdentity(observation))
			continue
		}
		if consumed[exceptionIndex] {
			add("exception-reused", observationIdentity(observation))
			continue
		}
		consumed[exceptionIndex] = true
	}
	return findings
}

func validateObservation(expected evidence.Expected, observation Observation) error {
	if observation.Tool != expected.Tool || observation.CommandID != expected.CommandID {
		return fmt.Errorf("tool/command identity does not match expected producer")
	}
	if err := nonemptyText("rule", observation.Rule); err != nil {
		return err
	}
	if err := nonemptyText("fingerprint", observation.Fingerprint); err != nil {
		return err
	}
	if err := pathpolicy.Validate("scope", observation.Scope); err != nil || observation.Scope == "." {
		return fmt.Errorf("scope must be an exact non-root repository path")
	}
	if observation.Source != SourceAnalyzer && observation.Source != SourceInline && observation.Source != SourceIgnoreFile {
		return fmt.Errorf("unsupported source %q", observation.Source)
	}
	if !observation.Suppressed && observation.Source != SourceAnalyzer {
		return fmt.Errorf("unsuppressed finding must come from analyzer output")
	}
	return nil
}

func executionCode(state ExecutionState, applicable bool) string {
	switch state {
	case ExecutionFailed:
		return "execution-failed"
	case ExecutionCancelled:
		return "execution-cancelled"
	case ExecutionTimedOut:
		return "execution-timed-out"
	case ExecutionSkipped:
		if applicable {
			return "unexpected-skip"
		}
		return "invalid-na-execution"
	case ExecutionCompleted:
		return "invalid-na-execution"
	default:
		return "invalid-execution"
	}
}

func observationIdentity(observation Observation) string {
	return observation.Tool + "/" + observation.Rule + "/" + observation.Fingerprint + "/" + observation.Scope
}

func nonemptyText(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}

func compareFinding(left, right Finding) int {
	if comparison := strings.Compare(left.Tool, right.Tool); comparison != 0 {
		return comparison
	}
	if comparison := strings.Compare(left.CommandID, right.CommandID); comparison != 0 {
		return comparison
	}
	if comparison := strings.Compare(left.Code, right.Code); comparison != 0 {
		return comparison
	}
	return strings.Compare(left.Detail, right.Detail)
}
