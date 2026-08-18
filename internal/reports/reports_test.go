package reports

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestCountNativeReports(t *testing.T) {
	tests := []struct {
		tool     string
		fixture  string
		findings int
	}{
		{tool: "sarif", fixture: "sarif.json"},
		{tool: "sarif", fixture: "sarif-levels.json", findings: 4},
		{tool: "golangci-lint", fixture: "golangci-lint.json", findings: 1},
		{tool: "govulncheck", fixture: "govulncheck.json", findings: 1},
		{tool: "staticcheck", fixture: "staticcheck.jsonl", findings: 1},
		{tool: "shellcheck", fixture: "shellcheck.json", findings: 1},
		{tool: "gitleaks", fixture: "gitleaks.json", findings: 1},
		{tool: "osv-scanner", fixture: "osv-scanner.json", findings: 1},
		{tool: "trivy", fixture: "trivy.json", findings: 4},
		{tool: "grype", fixture: "grype.json", findings: 1},
		{tool: "semgrep", fixture: "semgrep.json", findings: 1},
		{tool: "checkov", fixture: "checkov.json", findings: 1},
		{tool: "actionlint", fixture: "actionlint.json", findings: 1},
		{tool: "spdx", fixture: "spdx.json"},
		{tool: "license", fixture: "license.json", findings: 1},
	}

	for _, test := range tests {
		t.Run(test.tool+"/"+test.fixture, func(t *testing.T) {
			directory := "findings"
			if test.findings == 0 {
				directory = "clean"
			}
			result, err := Count(test.tool, bytes.NewReader(reportFixture(t, directory, test.fixture)))
			if err != nil {
				t.Fatalf("Count() error = %v", err)
			}
			if result.Findings != test.findings {
				t.Fatalf("Count() findings = %d, want %d", result.Findings, test.findings)
			}
		})
	}
}

func TestCountCheckovAcceptsEmptyResourceSummary(t *testing.T) {
	report := `{"passed":0,"failed":0,"skipped":0,"parsing_errors":0,"resource_count":0,"checkov_version":"3.3.11"}`
	result, err := Count("checkov", strings.NewReader(report))
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if result.Findings != 0 {
		t.Fatalf("Count() findings = %d, want 0", result.Findings)
	}
}

func TestEveryParserAcceptsCleanFixture(t *testing.T) {
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
	for tool, fixture := range fixtures {
		t.Run(tool, func(t *testing.T) {
			result, err := Count(tool, bytes.NewReader(reportFixture(t, "clean", fixture)))
			if err != nil {
				t.Fatalf("Count() error = %v", err)
			}
			if result.Findings != 0 {
				t.Fatalf("Count() findings = %d, want 0", result.Findings)
			}
		})
	}
}

func TestCountRejectsInvalidInput(t *testing.T) {
	for _, tool := range supportedTools() {
		t.Run(tool+"/empty", func(t *testing.T) {
			_, err := Count(tool, strings.NewReader(" \n\t"))
			if err == nil || !strings.Contains(err.Error(), "empty") {
				t.Fatalf("Count() error = %v, want empty input error", err)
			}
		})
		t.Run(tool+"/truncated", func(t *testing.T) {
			_, err := Count(tool, bytes.NewReader(reportFixture(t, "malformed", "truncated.json.invalid")))
			if err == nil {
				t.Fatal("Count() accepted truncated input")
			}
		})
	}

	t.Run("unknown tool", func(t *testing.T) {
		_, err := Count("unknown", strings.NewReader("{}"))
		if err == nil || !strings.Contains(err.Error(), "unsupported report tool") {
			t.Fatalf("Count() error = %v", err)
		}
	})
	t.Run("nil reader", func(t *testing.T) {
		_, err := Count("sarif", nil)
		if err == nil || !strings.Contains(err.Error(), "nil") {
			t.Fatalf("Count() error = %v", err)
		}
	})
}

func TestCountRejectsOversizedInput(t *testing.T) {
	reader := io.MultiReader(
		bytes.NewReader(reportFixture(t, "clean", "sarif.json")),
		io.LimitReader(repeatingReader(' '), MaxInputBytes),
	)
	_, err := Count("sarif", reader)
	if err == nil || !strings.Contains(err.Error(), "exceeds 67108864 byte limit") {
		t.Fatalf("Count() error = %v, want size limit error", err)
	}
}

func TestCountSARIFRejectsUnknownField(t *testing.T) {
	_, err := Count("sarif", bytes.NewReader(reportFixture(t, "malformed", "sarif-unknown-field.json.invalid")))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Count() error = %v, want unknown field", err)
	}
}

func TestCountSARIFRejectsDuplicateResult(t *testing.T) {
	_, err := Count("sarif", bytes.NewReader(reportFixture(t, "malformed", "sarif-duplicate-result.json.invalid")))
	if err == nil || !strings.Contains(err.Error(), "duplicate SARIF result") {
		t.Fatalf("Count() error = %v, want duplicate result", err)
	}
}

func TestCountSARIFCountsEveryRun(t *testing.T) {
	result, err := Count("sarif", bytes.NewReader(reportFixture(t, "findings", "sarif-multi-run.json")))
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if result.Findings != 3 {
		t.Fatalf("Count() findings = %d, want 3", result.Findings)
	}
}

func TestCountSARIFRejectsFailedOrExternalizedRuns(t *testing.T) {
	tests := []struct {
		fixture string
		want    string
	}{
		{fixture: "sarif-invocation-failed.json.invalid", want: "executionSuccessful"},
		{fixture: "sarif-invocation-missing-success.json.invalid", want: "executionSuccessful"},
		{fixture: "sarif-tool-execution-error.json.invalid", want: "toolExecutionNotifications"},
		{fixture: "sarif-tool-configuration-error.json.invalid", want: "toolConfigurationNotifications"},
		{fixture: "sarif-external-property-references.json.invalid", want: "externalPropertyFileReferences"},
		{fixture: "sarif-inline-external-properties.json.invalid", want: "inlineExternalProperties"},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			_, err := Count("sarif", bytes.NewReader(reportFixture(t, "malformed", test.fixture)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Count() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCountSARIFRequiresCompletedScannerRun(t *testing.T) {
	for _, fixture := range []string{"sarif-runs-null.json.invalid", "sarif-runs-empty.json.invalid"} {
		t.Run(fixture, func(t *testing.T) {
			_, err := Count("sarif", bytes.NewReader(reportFixture(t, "malformed", fixture)))
			if err == nil || !strings.Contains(err.Error(), "runs") {
				t.Fatalf("Count() error = %v, want completed scanner runs error", err)
			}
		})
	}
}

func TestCountSARIFRejectsMissingDriverWithoutInvocations(t *testing.T) {
	_, err := Count("sarif", bytes.NewReader(reportFixture(t, "malformed", "sarif-tool-missing-driver.json.invalid")))
	if err == nil || !strings.Contains(err.Error(), "driver") {
		t.Fatalf("Count() error = %v, want missing driver error", err)
	}
}

func TestCountSARIFResolvesNotificationLevels(t *testing.T) {
	tests := []struct {
		name    string
		class   string
		fixture string
		want    string
	}{
		{name: "explicit and inherited non-error levels", class: "clean", fixture: "sarif-notification-level-resolution.json"},
		{name: "id-only no-metadata defaults warning", class: "clean", fixture: "sarif-notification-id-only-no-metadata.json"},
		{name: "driver descriptor default error", class: "malformed", fixture: "sarif-notification-driver-default-error.json.invalid", want: "level error"},
		{name: "extension descriptor default error", class: "malformed", fixture: "sarif-notification-extension-default-error.json.invalid", want: "level error"},
		{name: "invocation override error", class: "malformed", fixture: "sarif-notification-override-error.json.invalid", want: "level error"},
		{name: "id-only hides existing metadata", class: "malformed", fixture: "sarif-notification-id-only-existing-metadata.json.invalid", want: "index or guid"},
		{name: "malformed descriptor", class: "malformed", fixture: "sarif-notification-malformed-descriptor.json.invalid", want: "nonnegative integer"},
		{name: "unresolved descriptor", class: "malformed", fixture: "sarif-notification-unresolved-descriptor.json.invalid", want: "does not resolve"},
		{name: "conflicting descriptor identity", class: "malformed", fixture: "sarif-notification-conflicting-descriptor.json.invalid", want: "does not resolve"},
		{name: "malformed override", class: "malformed", fixture: "sarif-notification-malformed-override.json.invalid", want: "configuration"},
		{name: "missing message", class: "malformed", fixture: "sarif-notification-missing-message.json.invalid", want: "message"},
		{name: "empty message", class: "malformed", fixture: "sarif-notification-empty-message.json.invalid", want: "message"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Count("sarif", bytes.NewReader(reportFixture(t, test.class, test.fixture)))
			if test.want == "" {
				if err != nil {
					t.Fatalf("Count() error = %v", err)
				}
				if result.Findings != 0 {
					t.Fatalf("Count() findings = %d, want 0", result.Findings)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Count() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCountSARIFValidatesNotificationMessages(t *testing.T) {
	tests := []struct {
		name    string
		class   string
		fixture string
		want    string
	}{
		{name: "valid forms", class: "clean", fixture: "sarif-notification-messages.json"},
		{name: "unknown only", class: "malformed", fixture: "sarif-notification-message-unknown-only.json.invalid", want: "message"},
		{name: "empty text", class: "malformed", fixture: "sarif-notification-message-empty-text.json.invalid", want: "text"},
		{name: "empty id", class: "malformed", fixture: "sarif-notification-message-empty-id.json.invalid", want: "id"},
		{name: "empty markdown", class: "malformed", fixture: "sarif-notification-message-empty-markdown.json.invalid", want: "markdown"},
		{name: "markdown without text", class: "malformed", fixture: "sarif-notification-message-markdown-without-text.json.invalid", want: "text"},
		{name: "wrong arguments", class: "malformed", fixture: "sarif-notification-message-wrong-arguments.json.invalid", want: "arguments"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Count("sarif", bytes.NewReader(reportFixture(t, test.class, test.fixture)))
			if test.want == "" {
				if err != nil {
					t.Fatalf("Count() error = %v", err)
				}
				if result.Findings != 0 {
					t.Fatalf("Count() findings = %d, want 0", result.Findings)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Count() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCountSARIFRejectsNotificationMessageTypesAndKeys(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    string
	}{
		{name: "text type", message: `{"text":1}`, want: "text"},
		{name: "id type", message: `{"id":1}`, want: "id"},
		{name: "markdown type", message: `{"text":"plain","markdown":1}`, want: "markdown"},
		{name: "properties type", message: `{"text":"plain","properties":[]}`, want: "properties"},
		{name: "unsupported key", message: `{"text":"plain","unexpected":true}`, want: "unexpected"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"scanner"}},"invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[{"message":` + test.message + `}]}],"results":[]}]}`
			_, err := Count("sarif", strings.NewReader(data))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Count() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCountSARIFValidatesAssociatedRuleReferences(t *testing.T) {
	tests := []struct {
		name    string
		class   string
		fixture string
		want    string
	}{
		{name: "driver extension and id-only", class: "clean", fixture: "sarif-notification-associated-rules.json"},
		{name: "unresolved", class: "malformed", fixture: "sarif-notification-associated-rule-unresolved.json.invalid", want: "does not resolve"},
		{name: "conflicting", class: "malformed", fixture: "sarif-notification-associated-rule-conflicting.json.invalid", want: "does not resolve"},
		{name: "ambiguous", class: "malformed", fixture: "sarif-notification-associated-rule-ambiguous.json.invalid", want: "ambiguous"},
		{name: "id-only hides metadata", class: "malformed", fixture: "sarif-notification-associated-rule-id-only-existing.json.invalid", want: "index or guid"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Count("sarif", bytes.NewReader(reportFixture(t, test.class, test.fixture)))
			if test.want == "" {
				if err != nil {
					t.Fatalf("Count() error = %v", err)
				}
				if result.Findings != 0 {
					t.Fatalf("Count() findings = %d, want 0", result.Findings)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Count() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCountSARIFValidatesConsumedGUIDs(t *testing.T) {
	tests := []struct {
		name    string
		class   string
		fixture string
		valid   bool
	}{
		{name: "uppercase valid", class: "clean", fixture: "sarif-notification-associated-rules.json", valid: true},
		{name: "component metadata", class: "malformed", fixture: "sarif-guid-component-metadata.json.invalid"},
		{name: "notification metadata", class: "malformed", fixture: "sarif-guid-notification-metadata.json.invalid"},
		{name: "rule metadata", class: "malformed", fixture: "sarif-guid-rule-metadata.json.invalid"},
		{name: "notification reference", class: "malformed", fixture: "sarif-guid-notification-reference.json.invalid"},
		{name: "associated rule reference", class: "malformed", fixture: "sarif-guid-associated-rule-reference.json.invalid"},
		{name: "component reference", class: "malformed", fixture: "sarif-guid-component-reference.json.invalid"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Count("sarif", bytes.NewReader(reportFixture(t, test.class, test.fixture)))
			if test.valid {
				if err != nil {
					t.Fatalf("Count() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "SARIF GUID pattern") {
				t.Fatalf("Count() error = %v, want SARIF GUID pattern error", err)
			}
		})
	}
}

func TestCountSARIFAcceptsRootPropertiesAndWarningNotifications(t *testing.T) {
	result, err := Count("sarif", bytes.NewReader(reportFixture(t, "clean", "sarif-properties-warning.json")))
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if result.Findings != 0 {
		t.Fatalf("Count() findings = %d, want 0", result.Findings)
	}
}

func TestCountReturnsParserErrorsSeparatelyFromFindings(t *testing.T) {
	for _, test := range []struct {
		tool    string
		fixture string
	}{
		{tool: "semgrep", fixture: "semgrep-error.json.invalid"},
		{tool: "checkov", fixture: "checkov-error.json.invalid"},
	} {
		t.Run(test.tool, func(t *testing.T) {
			result, err := Count(test.tool, bytes.NewReader(reportFixture(t, "malformed", test.fixture)))
			if err == nil {
				t.Fatal("Count() accepted native parser errors")
			}
			if result.Findings != 0 {
				t.Fatalf("Count() findings = %d after parser error, want 0", result.Findings)
			}
		})
	}
}

func TestCountRejectsIncompleteNativeEnvelope(t *testing.T) {
	tests := []struct {
		name string
		tool string
		json string
	}{
		{name: "golangci-lint report", tool: "golangci-lint", json: `{"Issues":[]}`},
		{name: "repeated govulncheck config", tool: "govulncheck", json: "{\"config\":{\"protocol_version\":\"v1.0.0\"}}\n{\"config\":{\"protocol_version\":\"v1.0.0\"}}"},
		{name: "null govulncheck progress", tool: "govulncheck", json: "{\"config\":{\"protocol_version\":\"v1.0.0\"}}\n{\"progress\":null}"},
		{name: "trivy schema", tool: "trivy", json: `{"Results":[]}`},
		{name: "grype metadata", tool: "grype", json: `{"matches":[]}`},
		{name: "checkov summary", tool: "checkov", json: `{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[],"parsing_errors":[]}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Count(test.tool, strings.NewReader(test.json))
			if err == nil {
				t.Fatal("Count() accepted an incomplete native report envelope")
			}
		})
	}
}

func TestCountRejectsMissingNestedFindingMembers(t *testing.T) {
	tests := []struct {
		tool    string
		fixture string
		want    string
	}{
		{tool: "osv-scanner", fixture: "osv-missing-packages.json.invalid", want: "packages"},
		{tool: "osv-scanner", fixture: "osv-missing-vulnerabilities.json.invalid", want: "vulnerabilities"},
		{tool: "trivy", fixture: "trivy-missing-target.json.invalid", want: "Target"},
		{tool: "checkov", fixture: "checkov-missing-failed-checks.json.invalid", want: "failed_checks"},
		{tool: "checkov", fixture: "checkov-missing-parsing-errors.json.invalid", want: "parsing_errors"},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			_, err := Count(test.tool, bytes.NewReader(reportFixture(t, "malformed", test.fixture)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Count() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCountStaticcheckRequiresSuccessfulRunnerEnvelope(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "raw native JSONL",
			data: `{"code":"SA1000","severity":"error","message":"finding"}` + "\n",
			want: "runner envelope",
		},
		{
			name: "failed execution",
			data: `{"schema_version":"1","parser":"staticcheck-jsonl-v1","execution_successful":false}` + "\n",
			want: "execution_successful",
		},
		{
			name: "wrong parser",
			data: `{"schema_version":"1","parser":"staticcheck-json-v2","execution_successful":true}` + "\n",
			want: "parser",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Count("staticcheck", strings.NewReader(test.data))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Count() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestStaticcheckRunnerEnvelopePreservesNativeJSONLPayload(t *testing.T) {
	wantPayload := []byte("{\"code\":\"SA1000\",\"severity\":\"error\",\"location\":{\"file\":\"main.go\",\"line\":1,\"column\":1},\"end\":{\"file\":\"main.go\",\"line\":1,\"column\":2},\"message\":\"finding\"}\n")
	data := append([]byte(`{"schema_version":"1","parser":"staticcheck-jsonl-v1","execution_successful":true}`+"\n"), wantPayload...)
	parts := bytes.SplitN(data, []byte("\n"), 2)
	if len(parts) != 2 {
		t.Fatal("staticcheck fixture has no runner envelope line")
	}
	var envelope struct {
		SchemaVersion       string `json:"schema_version"`
		Parser              string `json:"parser"`
		ExecutionSuccessful bool   `json:"execution_successful"`
	}
	if err := json.Unmarshal(parts[0], &envelope); err != nil {
		t.Fatalf("decode runner envelope: %v", err)
	}
	if envelope.SchemaVersion != "1" || envelope.Parser != "staticcheck-jsonl-v1" || !envelope.ExecutionSuccessful {
		t.Fatalf("runner envelope = %+v", envelope)
	}
	if !bytes.Equal(parts[1], wantPayload) {
		t.Fatalf("native payload changed:\n got: %q\nwant: %q", parts[1], wantPayload)
	}

	result, err := Count("staticcheck", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if result.Findings != 1 {
		t.Fatalf("Count() findings = %d, want 1", result.Findings)
	}
}

func reportFixture(t fixtureReader, class, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/reports/" + class + "/" + name)
	if err != nil {
		t.Fatalf("read fixture %s/%s: %v", class, name, err)
	}
	return data
}

func supportedTools() []string {
	return []string{"sarif", "golangci-lint", "govulncheck", "staticcheck", "shellcheck", "gitleaks", "osv-scanner", "trivy", "grype", "semgrep", "checkov"}
}

type repeatingReader byte

func (reader repeatingReader) Read(data []byte) (int, error) {
	for index := range data {
		data[index] = byte(reader)
	}
	return len(data), nil
}
