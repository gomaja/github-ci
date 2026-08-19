package reports

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const gremlinsModule = "example.com/module"

func TestValidateGremlinsAcceptsCompletePinnedReport(t *testing.T) {
	report := mustGremlinsFixture(t)
	if err := ValidateGremlins(bytes.NewReader(report), gremlinsModule); err != nil {
		t.Fatalf("ValidateGremlins() error = %v", err)
	}
}

func TestValidateGremlinsNoResultsProducesModuleBoundEvidence(t *testing.T) {
	transcript := "Starting...\nGathering coverage... done in 250ms\n\nNo results to report.\n"
	evidence, err := ValidateGremlinsNoResults(strings.NewReader(transcript), gremlinsModule)
	if err != nil {
		t.Fatalf("ValidateGremlinsNoResults() error = %v", err)
	}
	want := GremlinsNoResultsEvidence{
		SchemaVersion: 1,
		Tool:          "gremlins",
		ToolVersion:   "0.6.0",
		GoModule:      gremlinsModule,
		Outcome:       "no-mutants",
	}
	if evidence != want {
		t.Fatalf("ValidateGremlinsNoResults() = %#v, want %#v", evidence, want)
	}
}

func TestValidateGremlinsNoResultsRejectsUnprovenOutcome(t *testing.T) {
	tests := []struct {
		name       string
		transcript string
		module     string
		want       string
	}{
		{name: "empty", module: gremlinsModule, want: "empty report"},
		{name: "wrong case", transcript: "No Results To Report.\n", module: gremlinsModule, want: "exactly once"},
		{name: "embedded", transcript: "prefix No results to report.\n", module: gremlinsModule, want: "exactly once"},
		{name: "duplicate", transcript: "No results to report.\nNo results to report.\n", module: gremlinsModule, want: "exactly once"},
		{name: "trailing output", transcript: "No results to report.\nunexpected\n", module: gremlinsModule, want: "final non-empty line"},
		{name: "empty module", transcript: "No results to report.\n", want: "expected module"},
		{name: "control module", transcript: "No results to report.\n", module: "example.com/control\n", want: "control character"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateGremlinsNoResults(strings.NewReader(test.transcript), test.module)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateGremlinsNoResults() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateGremlinsRejectsMalformedOrInconsistentEvidence(t *testing.T) {
	valid := string(mustGremlinsFixture(t))
	tests := []struct {
		name   string
		report string
		module string
		want   string
	}{
		{name: "wrong module", report: valid, module: "example.com/other", want: "go_module"},
		{name: "empty expected module", report: valid, want: "expected module"},
		{name: "duplicate key", report: strings.Replace(valid, `"test_efficacy":100`, `"test_efficacy":100,"test_efficacy":100`, 1), module: gremlinsModule, want: "duplicate JSON key"},
		{name: "case-folded duplicate key", report: strings.Replace(valid, `"test_efficacy":100`, `"test_efficacy":100,"TEST_EFFICACY":100`, 1), module: gremlinsModule, want: "duplicate JSON key"},
		{name: "noncanonical root key", report: strings.Replace(valid, `"go_module"`, `"GO_MODULE"`, 1), module: gremlinsModule, want: "canonical property name"},
		{name: "noncanonical nested key", report: strings.Replace(valid, `"file_name"`, `"FILE_NAME"`, 1), module: gremlinsModule, want: "canonical property name"},
		{name: "unicode case variant", report: strings.Replace(valid, `"mutants_killed"`, `"mutants_Killed"`, 1), module: gremlinsModule, want: "canonical property name"},
		{name: "unknown root field", report: strings.Replace(valid, `"go_module":`, `"unknown":true,"go_module":`, 1), module: gremlinsModule, want: "unknown field"},
		{name: "missing module", report: strings.Replace(valid, `"go_module":"example.com/module",`, "", 1), module: gremlinsModule, want: "go_module is required"},
		{name: "null module", report: strings.Replace(valid, `"go_module":"example.com/module"`, `"go_module":null`, 1), module: gremlinsModule, want: "go_module is required"},
		{name: "missing files", report: strings.Replace(valid, `"files":[{"file_name":"internal/code.go","mutations":[{"type":"CONDITIONALS_NEGATION","status":"KILLED","line":10,"column":4},{"type":"ARITHMETIC_BASE","status":"NOT VIABLE","line":12,"column":8}]}],`, "", 1), module: gremlinsModule, want: "files is required"},
		{name: "null files", report: strings.Replace(valid, `"files":[{"file_name":"internal/code.go","mutations":[{"type":"CONDITIONALS_NEGATION","status":"KILLED","line":10,"column":4},{"type":"ARITHMETIC_BASE","status":"NOT VIABLE","line":12,"column":8}]}]`, `"files":null`, 1), module: gremlinsModule, want: "files is required"},
		{name: "empty files", report: strings.Replace(valid, `"files":[{"file_name":"internal/code.go","mutations":[{"type":"CONDITIONALS_NEGATION","status":"KILLED","line":10,"column":4},{"type":"ARITHMETIC_BASE","status":"NOT VIABLE","line":12,"column":8}]}]`, `"files":[]`, 1), module: gremlinsModule, want: "at least one file"},
		{name: "missing file name", report: strings.Replace(valid, `"file_name":"internal/code.go",`, "", 1), module: gremlinsModule, want: "file_name is required"},
		{name: "unsafe file", report: strings.Replace(valid, "internal/code.go", "../code.go", 1), module: gremlinsModule, want: "gremlins file_name"},
		{name: "duplicate file", report: strings.Replace(valid, `"files":[`, `"files":[{"file_name":"internal/code.go","mutations":[{"type":"CONDITIONALS_NEGATION","status":"KILLED","line":10,"column":4}]},`, 1), module: gremlinsModule, want: "duplicate file_name"},
		{name: "missing mutations", report: strings.Replace(valid, `,"mutations":[{"type":"CONDITIONALS_NEGATION","status":"KILLED","line":10,"column":4},{"type":"ARITHMETIC_BASE","status":"NOT VIABLE","line":12,"column":8}]`, "", 1), module: gremlinsModule, want: "mutations is required"},
		{name: "empty mutations", report: strings.Replace(valid, `"mutations":[{"type":"CONDITIONALS_NEGATION","status":"KILLED","line":10,"column":4},{"type":"ARITHMETIC_BASE","status":"NOT VIABLE","line":12,"column":8}]`, `"mutations":[]`, 1), module: gremlinsModule, want: "mutations must not be empty"},
		{name: "unknown file field", report: strings.Replace(valid, `"file_name":"internal/code.go"`, `"file_name":"internal/code.go","unknown":true`, 1), module: gremlinsModule, want: "unknown field"},
		{name: "missing mutation type", report: strings.Replace(valid, `"type":"CONDITIONALS_NEGATION",`, "", 1), module: gremlinsModule, want: "type is required"},
		{name: "unknown mutation type", report: strings.Replace(valid, "CONDITIONALS_NEGATION", "UNKNOWN", 1), module: gremlinsModule, want: "unsupported mutation type"},
		{name: "missing mutation status", report: strings.Replace(valid, `"status":"KILLED",`, "", 1), module: gremlinsModule, want: "status is required"},
		{name: "blocking status", report: strings.Replace(valid, "KILLED", "TIMED OUT", 1), module: gremlinsModule, want: "blocking mutation status"},
		{name: "unknown status", report: strings.Replace(valid, "KILLED", "UNKNOWN", 1), module: gremlinsModule, want: "blocking mutation status"},
		{name: "missing line", report: strings.Replace(valid, `"line":10,`, "", 1), module: gremlinsModule, want: "line and column are required"},
		{name: "missing column", report: strings.Replace(valid, `,"column":4`, "", 1), module: gremlinsModule, want: "line and column are required"},
		{name: "zero line", report: strings.Replace(valid, `"line":10`, `"line":0`, 1), module: gremlinsModule, want: "positive line and column"},
		{name: "zero column", report: strings.Replace(valid, `"column":4`, `"column":0`, 1), module: gremlinsModule, want: "positive line and column"},
		{name: "duplicate mutation", report: strings.Replace(valid, `{"type":"ARITHMETIC_BASE"`, `{"type":"CONDITIONALS_NEGATION","status":"KILLED","line":10,"column":4},{"type":"ARITHMETIC_BASE"`, 1), module: gremlinsModule, want: "duplicate mutation"},
		{name: "unknown mutation field", report: strings.Replace(valid, `"column":4`, `"column":4,"unknown":true`, 1), module: gremlinsModule, want: "unknown field"},
		{name: "efficacy", report: strings.Replace(valid, `"test_efficacy":100`, `"test_efficacy":99`, 1), module: gremlinsModule, want: "test_efficacy"},
		{name: "missing efficacy", report: strings.Replace(valid, `"test_efficacy":100,`, "", 1), module: gremlinsModule, want: "test_efficacy is required"},
		{name: "coverage", report: strings.Replace(valid, `"mutations_coverage":100`, `"mutations_coverage":99`, 1), module: gremlinsModule, want: "mutations_coverage"},
		{name: "missing coverage", report: strings.Replace(valid, `"mutations_coverage":100,`, "", 1), module: gremlinsModule, want: "mutations_coverage is required"},
		{name: "missing total", report: strings.Replace(valid, `"mutants_total":2,`, "", 1), module: gremlinsModule, want: "mutants_total is required"},
		{name: "missing killed", report: strings.Replace(valid, `"mutants_killed":1,`, "", 1), module: gremlinsModule, want: "mutants_killed is required"},
		{name: "missing lived", report: strings.Replace(valid, `"mutants_lived":0,`, "", 1), module: gremlinsModule, want: "mutants_lived is required"},
		{name: "missing not viable", report: strings.Replace(valid, `"mutants_not_viable":1,`, "", 1), module: gremlinsModule, want: "mutants_not_viable is required"},
		{name: "missing not covered", report: strings.Replace(valid, `"mutants_not_covered":0,`, "", 1), module: gremlinsModule, want: "mutants_not_covered is required"},
		{name: "negative count", report: strings.Replace(valid, `"mutants_lived":0`, `"mutants_lived":-1`, 1), module: gremlinsModule, want: "must not be negative"},
		{name: "lived summary", report: strings.Replace(valid, `"mutants_lived":0`, `"mutants_lived":1`, 1), module: gremlinsModule, want: "mutants_lived"},
		{name: "inconsistent total", report: strings.Replace(valid, `"mutants_total":2`, `"mutants_total":3`, 1), module: gremlinsModule, want: "mutants_total"},
		{name: "missing elapsed", report: strings.Replace(valid, `"elapsed_time":1.5,`, "", 1), module: gremlinsModule, want: "elapsed_time is required"},
		{name: "negative elapsed", report: strings.Replace(valid, `"elapsed_time":1.5`, `"elapsed_time":-1`, 1), module: gremlinsModule, want: "elapsed_time must not be negative"},
		{name: "missing statistics", report: strings.Replace(valid, `,"mutator_statistics":{"arithmetic_base":1,"conditionals_negation":1}`, "", 1), module: gremlinsModule, want: "mutator_statistics is required"},
		{name: "null statistic", report: strings.Replace(valid, `"arithmetic_base":1`, `"arithmetic_base":null`, 1), module: gremlinsModule, want: "must be an integer"},
		{name: "negative statistic", report: strings.Replace(valid, `"arithmetic_base":1`, `"arithmetic_base":-1`, 1), module: gremlinsModule, want: "must not be negative"},
		{name: "inconsistent statistic", report: strings.Replace(valid, `"arithmetic_base":1`, `"arithmetic_base":2`, 1), module: gremlinsModule, want: "mutator statistic"},
		{name: "unknown statistic", report: strings.Replace(valid, `"arithmetic_base":1`, `"unknown":1`, 1), module: gremlinsModule, want: "unknown field"},
		{name: "trailing value", report: valid + `{}`, module: gremlinsModule, want: "trailing"},
		{name: "malformed trailing value", report: valid + `?`, module: gremlinsModule, want: "invalid character"},
		{name: "unclosed object", report: `{"go_module":"example.com/module"`, module: gremlinsModule, want: "EOF"},
		{name: "excessive nesting", report: `{"unknown":` + strings.Repeat("[", maxGremlinsJSONDepth) + `0` + strings.Repeat("]", maxGremlinsJSONDepth) + `}`, module: gremlinsModule, want: "nesting exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateGremlins(strings.NewReader(test.report), test.module)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateGremlins() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateGremlinsAcceptsZeroElapsedTime(t *testing.T) {
	valid := string(mustGremlinsFixture(t))
	report := strings.Replace(valid, `"elapsed_time":1.5`, `"elapsed_time":0`, 1)
	if err := ValidateGremlins(strings.NewReader(report), gremlinsModule); err != nil {
		t.Fatalf("ValidateGremlins() error = %v", err)
	}
}

func TestValidateGremlinsUniqueKeysAcceptsMaximumDepth(t *testing.T) {
	report := strings.Repeat("[", maxGremlinsJSONDepth) + `0` + strings.Repeat("]", maxGremlinsJSONDepth)
	if err := validateGremlinsUniqueKeys([]byte(report)); err != nil {
		t.Fatalf("validateGremlinsUniqueKeys() error = %v", err)
	}
}

func FuzzValidateGremlins(f *testing.F) {
	f.Add(mustGremlinsFixture(f), gremlinsModule)
	f.Add([]byte(`{"go_module":`), gremlinsModule)
	f.Fuzz(func(_ *testing.T, report []byte, module string) {
		_ = ValidateGremlins(bytes.NewReader(report), module)
	})
}

func FuzzValidateGremlinsNoResults(f *testing.F) {
	f.Add([]byte("No results to report.\n"), gremlinsModule)
	f.Add([]byte(""), "")
	f.Fuzz(func(_ *testing.T, transcript []byte, module string) {
		_, _ = ValidateGremlinsNoResults(bytes.NewReader(transcript), module)
	})
}

type fixtureTB interface {
	Helper()
	Fatalf(string, ...any)
}

func mustGremlinsFixture(t fixtureTB) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/reports/clean/gremlins.json")
	if err != nil {
		t.Fatalf("read Gremlins fixture: %v", err)
	}
	return data
}
