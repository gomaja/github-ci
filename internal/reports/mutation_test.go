package reports

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCountGovulncheckPreservesMessagePosition(t *testing.T) {
	report := strings.Join([]string{
		`{"config":{"protocol_version":"v1.0.0"}}`,
		`{"progress":{}}`,
		`{"unexpected":{}}`,
	}, "\n")
	_, err := countGovulncheck([]byte(report))
	if err == nil || !strings.Contains(err.Error(), "decode govulncheck message 2") {
		t.Fatalf("countGovulncheck() error = %v, want message 2 diagnostic", err)
	}
}

func TestValidateGovulncheckFindingUsesFindingValidation(t *testing.T) {
	_, err := validateGovulncheckMessage(govulncheckMessage{Finding: json.RawMessage(`[]`)}, 1)
	if err == nil || err.Error() != "govulncheck finding must be a JSON object" {
		t.Fatalf("validateGovulncheckMessage() error = %v", err)
	}
}

func TestCountOSVScannerValidatesExperimentalConfig(t *testing.T) {
	_, err := countOSVScanner([]byte(`{"results":[],"experimental_config":[]}`))
	if err == nil || err.Error() != "OSV-Scanner experimental_config must be a JSON object" {
		t.Fatalf("countOSVScanner() error = %v", err)
	}
}

func TestCountGrypeIncludesMatchesAndIgnoredMatches(t *testing.T) {
	report := `{"matches":[{"id":1},{"id":2}],"ignoredMatches":[{"id":3}],"source":{},"distro":{},"descriptor":{}}`
	findings, err := countGrype([]byte(report))
	if err != nil {
		t.Fatalf("countGrype() error = %v", err)
	}
	if findings != 3 {
		t.Fatalf("countGrype() = %d, want 3", findings)
	}
}

func TestCountCheckovSummaryRejectsUnknownFields(t *testing.T) {
	report := `{"passed":0,"failed":0,"skipped":0,"parsing_errors":0,"resource_count":0,"checkov_version":"3.3.11","unexpected":true}`
	findings, err := countCheckov([]byte(report))
	if findings != 0 {
		t.Fatalf("countCheckov() findings = %d, want 0", findings)
	}
	if err == nil || !strings.Contains(err.Error(), `unknown field "unexpected"`) {
		t.Fatalf("countCheckov() error = %v", err)
	}
}

func TestRequireJSONObjectReturnsDecodeError(t *testing.T) {
	err := requireJSONObject(json.RawMessage(`[]`), "finding")
	if err == nil || err.Error() != "finding must be a JSON object" {
		t.Fatalf("requireJSONObject() error = %v", err)
	}
}

func TestCountSARIFValidatesRootPropertiesShape(t *testing.T) {
	report := `{"version":"2.1.0","properties":[],"runs":[{"tool":{"driver":{"name":"scanner"}},"results":[]}]}`
	_, err := countSARIF([]byte(report))
	if err == nil || err.Error() != "SARIF root properties must be a JSON object" {
		t.Fatalf("countSARIF() error = %v", err)
	}
}

func TestCountSARIFDistinguishesResultsWithoutFingerprints(t *testing.T) {
	report := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"scanner"}},"results":[{"message":{"text":"one"}},{"message":{"text":"two"}}]}]}`
	findings, err := countSARIF([]byte(report))
	if err != nil {
		t.Fatalf("countSARIF() error = %v", err)
	}
	if findings != 2 {
		t.Fatalf("countSARIF() = %d, want 2", findings)
	}
}

func TestSARIFNotificationResolverComponentBoundaries(t *testing.T) {
	const driverGUID = "12345678-1234-4234-8234-123456789abc"
	const extensionGUID = "abcdefab-cdef-4abc-8def-abcdefabcdef"
	tool := fmt.Sprintf(`{"driver":{"name":"driver","guid":%q},"extensions":[{"name":"extension","guid":%q}]}`, driverGUID, extensionGUID)
	resolver, err := newSARIFNotificationResolver(json.RawMessage(tool))
	if err != nil {
		t.Fatalf("newSARIFNotificationResolver() error = %v", err)
	}

	for _, test := range []struct {
		name      string
		reference string
		want      int
		wantError string
	}{
		{name: "driver by guid", reference: fmt.Sprintf(`{"guid":%q}`, driverGUID), want: -1},
		{name: "driver by name", reference: `{"name":"driver"}`, want: -1},
		{name: "malformed index", reference: `{"index":"0"}`, wantError: "nonnegative integer"},
		{name: "index at extension length", reference: `{"index":1}`, wantError: "does not resolve"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, resolveErr := resolver.resolveComponent(json.RawMessage(test.reference))
			if test.wantError != "" {
				if resolveErr == nil || !strings.Contains(resolveErr.Error(), test.wantError) {
					t.Fatalf("resolveComponent() error = %v, want %q", resolveErr, test.wantError)
				}
				return
			}
			if resolveErr != nil || got != test.want {
				t.Fatalf("resolveComponent() = %d, %v; want %d, nil", got, resolveErr, test.want)
			}
		})
	}
}

func TestSARIFDescriptorSetMatchesVersionedIDs(t *testing.T) {
	set := sarifDescriptorSet{descriptorsByID: map[string][]int{"RULE": {0}}}
	for _, test := range []struct {
		reference string
		want      bool
	}{
		{reference: "RULE", want: true},
		{reference: "RULE/1", want: true},
		{reference: "/RULE"},
		{reference: "RULE/"},
		{reference: "RULE/1/2"},
		{reference: "OTHER/1"},
	} {
		if got := set.hasDescriptorID(test.reference); got != test.want {
			t.Errorf("hasDescriptorID(%q) = %t, want %t", test.reference, got, test.want)
		}
	}
}

func TestAggregateLimitIncludesTrailingNewline(t *testing.T) {
	for _, test := range []struct {
		encoded int
		want    bool
	}{
		{encoded: MaxInputBytes - 1, want: true},
		{encoded: MaxInputBytes},
		{encoded: MaxInputBytes + 1},
	} {
		if got := aggregateFitsWithNewline(test.encoded); got != test.want {
			t.Errorf("aggregateFitsWithNewline(%d) = %t, want %t", test.encoded, got, test.want)
		}
	}
}

func TestAddFindingCountsRejectsOnlyOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	got, err := addFindingCounts(maxInt-1, 1)
	if err != nil || got != maxInt {
		t.Fatalf("addFindingCounts(max-1, 1) = %d, %v; want %d, nil", got, err, maxInt)
	}
	if _, err := addFindingCounts(maxInt, 1); err == nil || err.Error() != "aggregate finding count overflow" {
		t.Fatalf("addFindingCounts(max, 1) error = %v", err)
	}
	for _, input := range [][2]int{{-1, 0}, {0, -1}} {
		if _, err := addFindingCounts(input[0], input[1]); err == nil || err.Error() != "aggregate finding count overflow" {
			t.Fatalf("addFindingCounts(%d, %d) error = %v", input[0], input[1], err)
		}
	}
}

func TestCountAggregateRejectsNegativeCancellationFromJUnitOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	reports := []NamedReport{
		{Module: "a", Data: []byte(`<testsuites tests="1" failures="1"></testsuites>`)},
		{Module: "b", Data: []byte(`<testsuites tests="1" failures="1"></testsuites>`)},
		{Module: "c", Data: fmt.Appendf(nil, `<testsuites tests="%d" failures="%d" errors="%d"></testsuites>`, maxInt, maxInt, maxInt)},
	}
	document := aggregateDocument{SchemaVersion: aggregateSchemaVersion, ParserTool: "junit"}
	for _, report := range reports {
		document.Reports = append(document.Reports, aggregateWire{
			Module: report.Module, SHA256: reportDigest(report.Data),
			Payload: base64.StdEncoding.EncodeToString(report.Data),
		})
	}
	aggregate, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal aggregate: %v", err)
	}
	result, err := Count("junit", bytes.NewReader(aggregate))
	if err == nil || !strings.Contains(err.Error(), "JUnit failures and errors overflow") {
		t.Fatalf("Count() = %#v, %v; want JUnit overflow rejection", result, err)
	}
}

func TestCountAggregateRequiresStrictModuleOrder(t *testing.T) {
	for _, test := range []struct {
		name    string
		modules []string
	}{
		{name: "duplicate", modules: []string{"module-a", "module-a"}},
		{name: "descending", modules: []string{"module-b", "module-a"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := countAggregate("command-status", aggregateForModules(t, test.modules))
			if err == nil || err.Error() != "aggregate reports must be sorted with unique modules" {
				t.Fatalf("countAggregate() error = %v", err)
			}
		})
	}
}

func TestReportSizeLimitBoundary(t *testing.T) {
	for _, test := range []struct {
		size int
		want bool
	}{
		{size: MaxInputBytes - 1, want: true},
		{size: MaxInputBytes, want: true},
		{size: MaxInputBytes + 1},
	} {
		if got := reportFitsLimit(test.size); got != test.want {
			t.Errorf("reportFitsLimit(%d) = %t, want %t", test.size, got, test.want)
		}
	}
}

func TestCountActionlintLocationBoundaries(t *testing.T) {
	valid := `[{"message":"message","filepath":"workflow.yml","line":1,"column":1,"kind":"kind","snippet":"snippet","end_column":1}]`
	findings, err := countActionlint([]byte(valid))
	if err != nil || findings != 1 {
		t.Fatalf("countActionlint(valid) = %d, %v; want 1, nil", findings, err)
	}

	for _, report := range []string{
		`[{"message":"message","filepath":"workflow.yml","line":0,"column":1,"kind":"kind","snippet":"snippet","end_column":1}]`,
		`[{"message":"message","filepath":"workflow.yml","line":1,"column":0,"kind":"kind","snippet":"snippet","end_column":1}]`,
		`[{"message":"message","filepath":"workflow.yml","line":1,"column":2,"kind":"kind","snippet":"snippet","end_column":1}]`,
	} {
		if _, invalidErr := countActionlint([]byte(report)); invalidErr == nil || !strings.Contains(invalidErr.Error(), "invalid location") {
			t.Fatalf("countActionlint(%s) error = %v", report, invalidErr)
		}
	}
}

func TestValidateSPDXStrictBoundaries(t *testing.T) {
	validPrefix := `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"document","documentNamespace":"https://example.test/spdx","creationInfo":{"created":"2026-08-19T00:00:00Z","creators":["Tool: test"]},`
	for _, test := range []struct {
		name    string
		report  string
		wantErr string
	}{
		{name: "package subject", report: validPrefix + `"packages":[{"SPDXID":"SPDXRef-Package"}],"documentDescribes":["SPDXRef-Package"]}`},
		{name: "file subject", report: validPrefix + `"files":[{"SPDXID":"SPDXRef-File"}],"documentDescribes":["SPDXRef-File"]}`},
		{name: "no subject", report: validPrefix + `"documentDescribes":["SPDXRef-Missing"]}`, wantErr: "no described subject"},
		{name: "creation shape", report: strings.Replace(validPrefix+`"packages":[{"SPDXID":"SPDXRef-Package"}],"documentDescribes":["SPDXRef-Package"]}`, `"creationInfo":{"created":"2026-08-19T00:00:00Z","creators":["Tool: test"]}`, `"creationInfo":[]`, 1), wantErr: "creationInfo must be a JSON object"},
		{name: "unknown root field", report: validPrefix + `"packages":[{"SPDXID":"SPDXRef-Package"}],"documentDescribes":["SPDXRef-Package"],"unexpected":true}`, wantErr: `unknown field "unexpected"`},
		{name: "invalid annotation", report: validPrefix + `"packages":[{"SPDXID":"SPDXRef-Package"}],"documentDescribes":["SPDXRef-Package"],"annotations":[null]}`, wantErr: "SPDX entry 0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateSPDX([]byte(test.report))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateSPDX() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateSPDX() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestCountJUnitAdditionAndZeroBoundaries(t *testing.T) {
	for _, test := range []struct {
		name    string
		report  string
		wantErr string
	}{
		{name: "zero tests", report: `<testsuites tests="0"></testsuites>`},
		{name: "root combined failures", report: `<testsuites tests="1" failures="1" errors="1"></testsuites>`, wantErr: "JUnit failures and errors exceed tests"},
		{name: "suite combined failures", report: `<testsuites tests="1"><testsuite tests="1" failures="1" errors="1"></testsuite></testsuites>`, wantErr: "testsuite 0 failures and errors exceed tests"},
		{name: "suite overflow", report: fmt.Sprintf(`<testsuites tests="0"><testsuite tests="%d" failures="%d" errors="%d"></testsuite></testsuites>`, int(^uint(0)>>1), int(^uint(0)>>1), int(^uint(0)>>1)), wantErr: "testsuite 0 failures and errors overflow"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := countJUnit([]byte(test.report))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("countJUnit() error = %v", err)
				}
				return
			}
			if err == nil || err.Error() != test.wantErr {
				t.Fatalf("countJUnit() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func aggregateForModules(t *testing.T, modules []string) []byte {
	t.Helper()
	payload := []byte(`{"schema_version":"1","execution_successful":true}`)
	reports := make([]aggregateWire, 0, len(modules))
	for _, module := range modules {
		reports = append(reports, aggregateWire{
			Module:  module,
			SHA256:  reportDigest(payload),
			Payload: "eyJzY2hlbWFfdmVyc2lvbiI6IjEiLCJleGVjdXRpb25fc3VjY2Vzc2Z1bCI6dHJ1ZX0=",
		})
	}
	data, err := json.Marshal(aggregateDocument{SchemaVersion: aggregateSchemaVersion, ParserTool: "command-status", Reports: reports})
	if err != nil {
		t.Fatalf("marshal aggregate: %v", err)
	}
	return data
}

func TestWriteAggregatePropagatesWriterFailure(t *testing.T) {
	report := []NamedReport{{Module: ".", Data: []byte(`{"schema_version":"1","execution_successful":true}`)}}
	err := WriteAggregate("command-status", report, errorWriter{})
	if err == nil || err.Error() != "write aggregate: write failed" {
		t.Fatalf("WriteAggregate() error = %v", err)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestAggregateRoundTripKeepsExactPayload(t *testing.T) {
	payload := []byte(`{"schema_version":"1","execution_successful":false}`)
	var output bytes.Buffer
	if err := WriteAggregate("command-status", []NamedReport{{Module: ".", Data: payload}}, &output); err != nil {
		t.Fatalf("WriteAggregate() error = %v", err)
	}
	var document aggregateDocument
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("decode aggregate: %v", err)
	}
	if len(document.Reports) != 1 || document.Reports[0].SHA256 != reportDigest(payload) {
		t.Fatalf("aggregate reports = %+v", document.Reports)
	}
}
