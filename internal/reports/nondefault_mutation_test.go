package reports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"
)

func TestStatusValidationChecksEachOperand(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
		want string
	}{
		{name: "non-integer count", run: func() error { _, err := requiredNonnegative("count", "invalid"); return err }, want: "nonnegative integer"},
		{name: "negative count", run: func() error { _, err := requiredNonnegative("count", "-1"); return err }, want: "nonnegative integer"},
		{name: "gopls schema", run: func() error {
			return goplsReportError([]byte("{\"schema_version\":\"2\",\"parser\":\"gopls-diagnostics-v1\",\"execution_successful\":true}\n"))
		}, want: "unsupported gopls"},
		{name: "gopls parser", run: func() error {
			return goplsReportError([]byte("{\"schema_version\":\"1\",\"parser\":\"other\",\"execution_successful\":true}\n"))
		}, want: "unsupported gopls"},
		{name: "gopls blank line", run: func() error {
			return goplsReportError([]byte("{\"schema_version\":\"1\",\"parser\":\"gopls-diagnostics-v1\",\"execution_successful\":true}\n \n"))
		}, want: "invalid gopls diagnostic"},
		{name: "gopls control character", run: func() error {
			return goplsReportError([]byte("{\"schema_version\":\"1\",\"parser\":\"gopls-diagnostics-v1\",\"execution_successful\":true}\nbroken.go:\x00diagnostic\n"))
		}, want: "invalid gopls diagnostic"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertErrorContains(t, test.run(), test.want)
		})
	}
}

func TestActionlintRequiresEveryTextField(t *testing.T) {
	base := map[string]any{
		"message": "message", "filepath": "workflow.yml", "line": 1, "column": 1,
		"kind": "kind", "snippet": "snippet", "end_column": 1,
	}
	for _, field := range []string{"message", "kind", "snippet"} {
		t.Run(field, func(t *testing.T) {
			finding := maps.Clone(base)
			finding[field] = " "
			_, err := countActionlint(mustJSON(t, []any{finding}))
			assertErrorContains(t, err, "incomplete")
		})
	}
}

func TestSPDXChecksEachRequiredIdentityAndMetadataField(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "version", mutate: func(document map[string]any) { document["spdxVersion"] = "SPDX-2.2" }, want: "identity"},
		{name: "data license", mutate: func(document map[string]any) { document["dataLicense"] = "other" }, want: "identity"},
		{name: "document id", mutate: func(document map[string]any) { document["SPDXID"] = "SPDXRef-Other" }, want: "identity"},
		{name: "name", mutate: func(document map[string]any) { document["name"] = " " }, want: "name or namespace"},
		{name: "namespace", mutate: func(document map[string]any) { document["documentNamespace"] = " " }, want: "name or namespace"},
		{name: "created", mutate: func(document map[string]any) {
			document["creationInfo"] = map[string]any{"creators": []any{"Tool: test"}}
		}, want: "creationInfo is incomplete"},
		{name: "creators", mutate: func(document map[string]any) {
			document["creationInfo"] = map[string]any{"created": "2026-08-19T00:00:00Z"}
		}, want: "creationInfo is incomplete"},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			document := validSPDXDocument()
			test.mutate(document)
			assertErrorContains(t, validateSPDX(mustJSON(t, document)), test.want)
		})
	}
}

func TestSPDXRelationshipRequiresEveryDescribesOperand(t *testing.T) {
	tests := []struct {
		name         string
		relationship map[string]any
	}{
		{name: "wrong relationship type", relationship: map[string]any{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "OTHER", "relatedSpdxElement": "SPDXRef-Package"}},
		{name: "wrong source and type", relationship: map[string]any{"spdxElementId": "SPDXRef-Other", "relationshipType": "OTHER", "relatedSpdxElement": "SPDXRef-Package"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validSPDXDocument()
			delete(document, "documentDescribes")
			document["relationships"] = []any{test.relationship}
			assertErrorContains(t, validateSPDX(mustJSON(t, document)), "no described subject")
		})
	}
}

func TestLicenseInventoryChecksEachRequiredField(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "dependencies null", mutate: func(inventory map[string]any) { inventory["dependencies"] = nil }, want: "must not be null"},
		{name: "violations null", mutate: func(inventory map[string]any) { inventory["violations"] = nil }, want: "must not be null"},
		{name: "dependency package", mutate: func(inventory map[string]any) {
			inventory["dependencies"] = []any{map[string]any{"package": " ", "license": "Apache-2.0"}}
		}, want: "dependency 0 is incomplete"},
		{name: "dependency license", mutate: func(inventory map[string]any) {
			inventory["dependencies"] = []any{map[string]any{"package": "module", "license": " "}}
		}, want: "dependency 0 is incomplete"},
		{name: "violation package", mutate: func(inventory map[string]any) {
			inventory["violations"] = []any{map[string]any{"package": " ", "license": "GPL-3.0", "reason": "denied"}}
		}, want: "violation 0 is incomplete"},
		{name: "violation license", mutate: func(inventory map[string]any) {
			inventory["violations"] = []any{map[string]any{"package": "module", "license": " ", "reason": "denied"}}
		}, want: "violation 0 is incomplete"},
		{name: "violation reason", mutate: func(inventory map[string]any) {
			inventory["violations"] = []any{map[string]any{"package": "module", "license": "GPL-3.0", "reason": " "}}
		}, want: "violation 0 is incomplete"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory := map[string]any{
				"schema_version": "1",
				"dependencies":   []any{},
				"violations":     []any{},
			}
			test.mutate(inventory)
			_, err := countLicenseInventory(mustJSON(t, inventory))
			assertErrorContains(t, err, test.want)
		})
	}
}

func TestNativeJSONParsersCheckEachCompoundOperand(t *testing.T) {
	for _, test := range []struct {
		name   string
		report map[string]any
		want   string
	}{
		{name: "semgrep results", report: map[string]any{"errors": []any{}}, want: "results and errors"},
		{name: "semgrep errors", report: map[string]any{"results": []any{}}, want: "results and errors"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := countSemgrep(mustJSON(t, test.report))
			assertErrorContains(t, err, test.want)
		})
	}

	for _, field := range []string{"passed", "failed", "skipped", "parsing_errors", "resource_count"} {
		t.Run("checkov "+field, func(t *testing.T) {
			summary := map[string]any{
				"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0,
				"resource_count": 0, "checkov_version": "3.3.11",
			}
			summary[field] = -1
			_, err := countCheckov(mustJSON(t, summary))
			assertErrorContains(t, err, "invalid Checkov summary")
		})
	}
	t.Run("checkov version", func(t *testing.T) {
		summary := map[string]any{
			"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0,
			"resource_count": 0, "checkov_version": " ",
		}
		_, err := countCheckov(mustJSON(t, summary))
		assertErrorContains(t, err, "invalid Checkov summary")
	})

	for _, test := range []struct {
		name string
		raw  json.RawMessage
	}{
		{name: "malformed OSV result", raw: json.RawMessage(`[]`)},
		{name: "empty OSV result", raw: json.RawMessage(`{}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := countOSVResult(test.raw, 0)
			assertErrorContains(t, err, "invalid OSV-Scanner result")
		})
	}
}

func TestNativeJSONParsersAccumulateAcrossEveryEntry(t *testing.T) {
	packageWithFinding := func(name string) map[string]any {
		return map[string]any{
			"package":         map[string]any{"name": name},
			"vulnerabilities": []any{map[string]any{"id": "OSV-1"}},
		}
	}
	result := func(name string) map[string]any {
		return map[string]any{"packages": []any{packageWithFinding(name)}}
	}

	findings, err := countOSVScanner(mustJSON(t, map[string]any{"results": []any{result("a"), result("b")}}))
	if err != nil || findings != 2 {
		t.Fatalf("countOSVScanner() = %d, %v; want 2, nil", findings, err)
	}
	findings, err = countOSVResult(mustJSON(t, map[string]any{"packages": []any{packageWithFinding("a"), packageWithFinding("b")}}), 0)
	if err != nil || findings != 2 {
		t.Fatalf("countOSVResult() = %d, %v; want 2, nil", findings, err)
	}

	emptyParsingErrors := []json.RawMessage{}
	firstFailures := []json.RawMessage{json.RawMessage(`{"id":1}`)}
	secondFailures := []json.RawMessage{json.RawMessage(`{"id":2}`), json.RawMessage(`{"id":3}`)}
	reports := []checkovReport{
		{Results: &checkovResults{FailedChecks: &firstFailures, ParsingErrors: &emptyParsingErrors}, Summary: json.RawMessage(`{"passed":0}`)},
		{Results: &checkovResults{FailedChecks: &secondFailures, ParsingErrors: &emptyParsingErrors}, Summary: json.RawMessage(`{"passed":0}`)},
	}
	findings, err = countCheckovReports(reports)
	if err != nil || findings != 3 {
		t.Fatalf("countCheckovReports() = %d, %v; want 3, nil", findings, err)
	}
}

func TestCodeQLNormalizationSkipsMalformedEntriesWithoutStopping(t *testing.T) {
	report := []byte(`{"runs":[{"invocations":{}},{"invocations":[{"toolExecutionNotifications":[{"message":[]},{"message":{"text":"kept"}},{"message":{"text":""}}]}]}]}`)
	normalized := normalizeCodeQLEmptyNotificationText(report)
	if bytes.Equal(normalized, report) {
		t.Fatal("normalizeCodeQLEmptyNotificationText() did not repair the later empty notification")
	}
	if !bytes.Contains(normalized, []byte(codeQLEmptyNotificationText)) {
		t.Fatalf("normalized report does not contain replacement text: %s", normalized)
	}
	if !bytes.Contains(normalized, []byte(`"text":"kept"`)) {
		t.Fatalf("normalized report did not preserve the nonempty message: %s", normalized)
	}
}

func TestSARIFInvocationRequiresAnObject(t *testing.T) {
	for _, invocation := range []string{"null", "1"} {
		t.Run(invocation, func(t *testing.T) {
			report := fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"scanner"}},"invocations":[%s],"results":[]}]}`, invocation)
			_, err := countSARIF([]byte(report))
			assertErrorContains(t, err, "must be a JSON object")
		})
	}
}

func TestSARIFNotificationMetadataChecksEachOperand(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  json.RawMessage
		run  func(json.RawMessage) error
	}{
		{name: "component name type", raw: json.RawMessage(`{"name":1}`), run: func(raw json.RawMessage) error { _, err := parseSARIFNotificationComponent(raw, "driver"); return err }},
		{name: "component name missing", raw: json.RawMessage(`{}`), run: func(raw json.RawMessage) error { _, err := parseSARIFNotificationComponent(raw, "driver"); return err }},
		{name: "component name empty", raw: json.RawMessage(`{"name":""}`), run: func(raw json.RawMessage) error { _, err := parseSARIFNotificationComponent(raw, "driver"); return err }},
		{name: "descriptor id type", raw: json.RawMessage(`{"id":1}`), run: func(raw json.RawMessage) error {
			_, err := parseSARIFReportingDescriptor(raw, "descriptor", false)
			return err
		}},
		{name: "descriptor id missing", raw: json.RawMessage(`{}`), run: func(raw json.RawMessage) error {
			_, err := parseSARIFReportingDescriptor(raw, "descriptor", false)
			return err
		}},
		{name: "descriptor id empty", raw: json.RawMessage(`{"id":""}`), run: func(raw json.RawMessage) error {
			_, err := parseSARIFReportingDescriptor(raw, "descriptor", false)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertErrorContains(t, test.run(test.raw), "nonempty string")
		})
	}
}

func TestSARIFReferenceAndOverrideOperands(t *testing.T) {
	descriptor := sarifReportingDescriptor{defaultLevel: sarifLevelWarning}
	resolution := sarifDescriptorResolution{key: sarifDescriptorKey{component: -1, descriptor: 0}, descriptor: &descriptor}
	if got := effectiveDescriptorLevel(resolution, true, map[sarifDescriptorKey]string{resolution.key: ""}); got != sarifLevelWarning {
		t.Fatalf("effectiveDescriptorLevel(empty override) = %q, want %q", got, sarifLevelWarning)
	}
	if got := effectiveDescriptorLevel(resolution, true, map[sarifDescriptorKey]string{resolution.key: sarifLevelError}); got != sarifLevelError {
		t.Fatalf("effectiveDescriptorLevel(error override) = %q, want %q", got, sarifLevelError)
	}

	for _, reference := range []json.RawMessage{json.RawMessage(`{"id":1}`), json.RawMessage(`{"id":""}`)} {
		_, err := parseSARIFDescriptorReference(reference)
		assertErrorContains(t, err, "nonempty string")
	}
}

func TestSARIFComponentReferenceChecksNameAndGUIDIndependently(t *testing.T) {
	const guid = "12345678-1234-4234-8234-123456789abc"
	resolver, err := newSARIFNotificationResolver(json.RawMessage(`{"driver":{"name":"driver","guid":"` + guid + `"}}`))
	if err != nil {
		t.Fatalf("newSARIFNotificationResolver() error = %v", err)
	}
	for _, test := range []struct {
		name      string
		reference json.RawMessage
		want      string
	}{
		{name: "empty name", reference: json.RawMessage(`{"name":""}`), want: "nonempty string"},
		{name: "name type", reference: json.RawMessage(`{"name":1}`), want: "nonempty string"},
		{name: "name mismatch", reference: json.RawMessage(`{"name":"other","guid":"` + guid + `"}`), want: "does not resolve"},
		{name: "guid mismatch", reference: json.RawMessage(`{"name":"driver","guid":"abcdefab-cdef-4abc-8def-abcdefabcdef"}`), want: "does not resolve"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, resolveErr := resolver.resolveComponent(test.reference)
			assertErrorContains(t, resolveErr, test.want)
		})
	}
}

func validSPDXDocument() map[string]any {
	return map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              "document",
		"documentNamespace": "https://example.test/spdx",
		"creationInfo": map[string]any{
			"created":  "2026-08-19T00:00:00Z",
			"creators": []any{"Tool: test"},
		},
		"packages":          []any{map[string]any{"SPDXID": "SPDXRef-Package"}},
		"documentDescribes": []any{"SPDXRef-Package"},
	}
}

func goplsReportError(data []byte) error {
	findings, err := countGopls(data)
	if findings != 0 {
		return fmt.Errorf("unexpected gopls findings: %d", findings)
	}
	return err
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test report: %v", err)
	}
	return data
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}
