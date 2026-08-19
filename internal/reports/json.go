package reports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

func countGolangCILint(data []byte) (int, error) {
	var report struct {
		Issues *[]json.RawMessage `json:"Issues"`
		Report json.RawMessage    `json:"Report"`
	}
	if err := decodeStrictJSON(data, &report); err != nil {
		return 0, err
	}
	if report.Issues == nil {
		return 0, errors.New("golangci-lint report has no Issues array")
	}
	if err := requireJSONObject(report.Report, "golangci-lint Report"); err != nil {
		return 0, err
	}
	if err := validateObjects(*report.Issues, "golangci-lint issue"); err != nil {
		return 0, err
	}
	return len(*report.Issues), nil
}

type govulncheckMessage struct {
	Config   json.RawMessage `json:"config,omitempty"`
	Progress json.RawMessage `json:"progress,omitempty"`
	SBOM     json.RawMessage `json:"SBOM,omitempty"`
	OSV      json.RawMessage `json:"osv,omitempty"`
	Finding  json.RawMessage `json:"finding,omitempty"`
}

func countGovulncheck(data []byte) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	messages := 0
	findings := 0
	for {
		var entry govulncheckMessage
		err := decoder.Decode(&entry)
		if errors.Is(err, io.EOF) {
			if messages == 0 {
				return 0, errors.New("empty govulncheck stream")
			}
			return findings, nil
		}
		if err != nil {
			return 0, fmt.Errorf("decode govulncheck message %d: %w", messages, err)
		}
		finding, err := validateGovulncheckMessage(entry, messages)
		if err != nil {
			return 0, err
		}
		if finding {
			findings++
		}
		messages++
	}
}

func validateGovulncheckMessage(entry govulncheckMessage, index int) (bool, error) {
	present := 0
	for _, field := range []json.RawMessage{entry.Config, entry.Progress, entry.SBOM, entry.OSV} {
		if field == nil {
			continue
		}
		present++
		if err := requireJSONObjectAllowEmpty(field, "govulncheck protocol field"); err != nil {
			return false, fmt.Errorf("message %d: %w", index, err)
		}
	}
	if entry.Finding != nil {
		present++
	}
	if present != 1 {
		return false, fmt.Errorf("govulncheck message %d must contain exactly one protocol field", index)
	}
	if index == 0 {
		if entry.Config == nil {
			return false, errors.New("first govulncheck message is not config")
		}
		return false, validateGovulncheckConfig(entry.Config)
	}
	if entry.Config != nil {
		return false, fmt.Errorf("govulncheck config repeated at message %d", index)
	}
	if entry.Finding == nil {
		return false, nil
	}
	if err := requireJSONObject(entry.Finding, "govulncheck finding"); err != nil {
		return false, err
	}
	return true, nil
}

func validateGovulncheckConfig(raw json.RawMessage) error {
	var config struct {
		ProtocolVersion string `json:"protocol_version"`
		ScannerName     string `json:"scanner_name,omitempty"`
		ScannerVersion  string `json:"scanner_version,omitempty"`
		DB              string `json:"db,omitempty"`
		DBLastModified  string `json:"db_last_modified,omitempty"`
		GoVersion       string `json:"go_version,omitempty"`
		ScanLevel       string `json:"scan_level,omitempty"`
		ScanMode        string `json:"scan_mode,omitempty"`
	}
	if err := decodeStrictJSON(raw, &config); err != nil {
		return fmt.Errorf("decode govulncheck config: %w", err)
	}
	if config.ProtocolVersion != "v1.0.0" {
		return fmt.Errorf("unsupported govulncheck protocol %q", config.ProtocolVersion)
	}
	return nil
}

func countStaticcheck(data []byte) (int, error) {
	payload, err := staticcheckNativePayload(data)
	if err != nil {
		return 0, err
	}
	if len(payload) == 0 {
		return 0, nil
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return 0, errors.New("staticcheck native JSONL payload contains only whitespace")
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	findings := 0
	for {
		var diagnostic json.RawMessage
		err := decoder.Decode(&diagnostic)
		if errors.Is(err, io.EOF) {
			return findings, nil
		}
		if err != nil {
			return 0, fmt.Errorf("decode staticcheck diagnostic %d: %w", findings, err)
		}
		if err := requireJSONObject(diagnostic, "staticcheck diagnostic"); err != nil {
			return 0, err
		}
		findings++
	}
}

const staticcheckJSONLParserIdentity = "staticcheck-jsonl-v1"

// staticcheckNativePayload keeps bytes after the first LF as the unchanged staticcheck -f json artifact.
func staticcheckNativePayload(data []byte) ([]byte, error) {
	before, after, ok := bytes.Cut(data, []byte{'\n'})
	if !ok {
		return nil, errors.New("staticcheck report has no runner envelope")
	}
	var envelope struct {
		SchemaVersion       string `json:"schema_version"`
		Parser              string `json:"parser"`
		ExecutionSuccessful *bool  `json:"execution_successful"`
	}
	if err := decodeStrictJSON(before, &envelope); err != nil {
		return nil, fmt.Errorf("decode staticcheck runner envelope: %w", err)
	}
	if envelope.SchemaVersion != "1" {
		return nil, fmt.Errorf("unsupported staticcheck runner envelope schema %q", envelope.SchemaVersion)
	}
	if envelope.Parser != staticcheckJSONLParserIdentity {
		return nil, fmt.Errorf("unsupported staticcheck parser %q", envelope.Parser)
	}
	if envelope.ExecutionSuccessful == nil || !*envelope.ExecutionSuccessful {
		return nil, errors.New("staticcheck runner execution_successful is not true")
	}
	return after, nil
}

func countJSONArray(data []byte) (int, error) {
	var findings []json.RawMessage
	if err := decodeStrictJSON(data, &findings); err != nil {
		return 0, err
	}
	if findings == nil {
		return 0, errors.New("report must be a JSON array")
	}
	if err := validateObjects(findings, "finding"); err != nil {
		return 0, err
	}
	return len(findings), nil
}

func countOSVScanner(data []byte) (int, error) {
	var report struct {
		Results              *[]json.RawMessage `json:"results"`
		ExperimentalAnalysis json.RawMessage    `json:"experimentalAnalysis,omitempty"`
		ExperimentalConfig   json.RawMessage    `json:"experimental_config,omitempty"`
	}
	if err := decodeStrictJSON(data, &report); err != nil {
		return 0, err
	}
	if report.Results == nil {
		return 0, errors.New("OSV-Scanner report has no results array")
	}
	if report.ExperimentalConfig != nil {
		if err := requireJSONObjectAllowEmpty(report.ExperimentalConfig, "OSV-Scanner experimental_config"); err != nil {
			return 0, err
		}
	}
	findings := 0
	for resultIndex, rawResult := range *report.Results {
		count, err := countOSVResult(rawResult, resultIndex)
		if err != nil {
			return 0, err
		}
		findings += count
	}
	return findings, nil
}

func countOSVResult(raw json.RawMessage, resultIndex int) (int, error) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil || len(result) == 0 {
		return 0, fmt.Errorf("invalid OSV-Scanner result %d", resultIndex)
	}
	packagesRaw, exists := result["packages"]
	if !exists {
		return 0, fmt.Errorf("OSV-Scanner result %d has no packages array", resultIndex)
	}
	var packages []map[string]json.RawMessage
	if err := json.Unmarshal(packagesRaw, &packages); err != nil {
		return 0, fmt.Errorf("decode OSV-Scanner result %d packages: %w", resultIndex, err)
	}
	if packages == nil {
		return 0, fmt.Errorf("OSV-Scanner result %d packages must be an array", resultIndex)
	}
	findings := 0
	for packageIndex, pkg := range packages {
		count, err := countOSVPackage(pkg, resultIndex, packageIndex)
		if err != nil {
			return 0, err
		}
		findings += count
	}
	return findings, nil
}

func countOSVPackage(pkg map[string]json.RawMessage, resultIndex, packageIndex int) (int, error) {
	if err := requireJSONObject(pkg["package"], "OSV-Scanner package identity"); err != nil {
		return 0, fmt.Errorf("result %d package %d: %w", resultIndex, packageIndex, err)
	}
	vulnerabilitiesRaw, exists := pkg["vulnerabilities"]
	if !exists {
		return 0, fmt.Errorf("OSV-Scanner result %d package %d has no vulnerabilities array", resultIndex, packageIndex)
	}
	var vulnerabilities []json.RawMessage
	if err := json.Unmarshal(vulnerabilitiesRaw, &vulnerabilities); err != nil {
		return 0, fmt.Errorf("decode OSV-Scanner result %d package %d vulnerabilities: %w", resultIndex, packageIndex, err)
	}
	if vulnerabilities == nil {
		return 0, fmt.Errorf("OSV-Scanner result %d package %d vulnerabilities must be an array", resultIndex, packageIndex)
	}
	if err := validateObjects(vulnerabilities, "OSV-Scanner vulnerability"); err != nil {
		return 0, err
	}
	return len(vulnerabilities), nil
}

func countTrivy(data []byte) (int, error) {
	type trivyResult struct {
		Target            string            `json:"Target"`
		Class             string            `json:"Class,omitempty"`
		Type              string            `json:"Type,omitempty"`
		Packages          []json.RawMessage `json:"Packages,omitempty"`
		Vulnerabilities   []json.RawMessage `json:"Vulnerabilities,omitempty"`
		MisconfSummary    json.RawMessage   `json:"MisconfSummary,omitempty"`
		Misconfigurations []json.RawMessage `json:"Misconfigurations,omitempty"`
		Secrets           []json.RawMessage `json:"Secrets,omitempty"`
		Licenses          []json.RawMessage `json:"Licenses,omitempty"`
		CustomResources   []json.RawMessage `json:"CustomResources,omitempty"`
		ModifiedFindings  []json.RawMessage `json:"ExperimentalModifiedFindings,omitempty"`
	}
	var report struct {
		SchemaVersion int             `json:"SchemaVersion,omitempty"`
		Trivy         json.RawMessage `json:"Trivy,omitempty"`
		ReportID      string          `json:"ReportID,omitempty"`
		CreatedAt     string          `json:"CreatedAt,omitempty"`
		ArtifactID    string          `json:"ArtifactID,omitempty"`
		ArtifactName  string          `json:"ArtifactName,omitempty"`
		ArtifactType  string          `json:"ArtifactType,omitempty"`
		Metadata      json.RawMessage `json:"Metadata,omitempty"`
		Results       json.RawMessage `json:"Results,omitempty"`
	}
	if err := decodeStrictJSON(data, &report); err != nil {
		return 0, err
	}
	if report.SchemaVersion != 2 {
		return 0, fmt.Errorf("unsupported trivy schema version %d", report.SchemaVersion)
	}
	if len(report.Results) == 0 {
		return 0, nil
	}
	if bytes.Equal(bytes.TrimSpace(report.Results), []byte("null")) {
		return 0, errors.New("trivy Results must be an array when present")
	}
	var results []trivyResult
	if err := json.Unmarshal(report.Results, &results); err != nil {
		return 0, fmt.Errorf("decode trivy Results: %w", err)
	}
	if results == nil {
		return 0, errors.New("trivy Results must be an array when present")
	}
	findings := 0
	for index, result := range results {
		if result.Target == "" {
			return 0, fmt.Errorf("trivy result %d has no Target identity", index)
		}
		groups := [][]json.RawMessage{result.Vulnerabilities, result.Misconfigurations, result.Secrets, result.Licenses, result.ModifiedFindings}
		for _, group := range groups {
			if err := validateObjects(group, fmt.Sprintf("Trivy result %d finding", index)); err != nil {
				return 0, err
			}
			findings += len(group)
		}
	}
	return findings, nil
}

func countGrype(data []byte) (int, error) {
	var report struct {
		Matches         *[]json.RawMessage `json:"matches"`
		IgnoredMatches  []json.RawMessage  `json:"ignoredMatches,omitempty"`
		AlertsByPackage json.RawMessage    `json:"alertsByPackage,omitempty"`
		Source          json.RawMessage    `json:"source"`
		Distro          json.RawMessage    `json:"distro"`
		Descriptor      json.RawMessage    `json:"descriptor"`
	}
	if err := decodeStrictJSON(data, &report); err != nil {
		return 0, err
	}
	if report.Matches == nil {
		return 0, errors.New("grype report has no matches array")
	}
	for _, field := range []json.RawMessage{report.Source, report.Distro, report.Descriptor} {
		if err := requireJSONObjectAllowEmpty(field, "grype metadata"); err != nil {
			return 0, err
		}
	}
	if err := validateObjects(*report.Matches, "Grype match"); err != nil {
		return 0, err
	}
	if err := validateObjects(report.IgnoredMatches, "Grype ignored match"); err != nil {
		return 0, err
	}
	return len(*report.Matches) + len(report.IgnoredMatches), nil
}

func countSemgrep(data []byte) (int, error) {
	var report struct {
		Version                string             `json:"version,omitempty"`
		Results                *[]json.RawMessage `json:"results"`
		Errors                 *[]json.RawMessage `json:"errors"`
		Paths                  json.RawMessage    `json:"paths,omitempty"`
		SkippedRules           []json.RawMessage  `json:"skipped_rules,omitempty"`
		Explanations           []json.RawMessage  `json:"explanations,omitempty"`
		Time                   json.RawMessage    `json:"time,omitempty"`
		EngineRequested        string             `json:"engine_requested,omitempty"`
		InterfileLanguagesUsed []string           `json:"interfile_languages_used,omitempty"`
		ProfilingResults       []json.RawMessage  `json:"profiling_results,omitempty"`
	}
	if err := decodeStrictJSON(data, &report); err != nil {
		return 0, err
	}
	if report.Results == nil || report.Errors == nil {
		return 0, errors.New("semgrep report requires results and errors arrays")
	}
	if len(*report.Errors) != 0 {
		return 0, fmt.Errorf("semgrep report contains %d parser errors", len(*report.Errors))
	}
	if err := validateObjects(*report.Results, "Semgrep result"); err != nil {
		return 0, err
	}
	return len(*report.Results), nil
}

func countCheckov(data []byte) (int, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return 0, errors.New("empty Checkov report")
	}
	if trimmed[0] == '[' {
		var reports []checkovReport
		if err := decodeStrictJSON(trimmed, &reports); err != nil {
			return 0, err
		}
		if len(reports) == 0 {
			return 0, errors.New("checkov report array is empty")
		}
		return countCheckovReports(reports)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &shape); err != nil {
		return 0, fmt.Errorf("decode Checkov report shape: %w", err)
	}
	if _, summaryOnly := shape["checkov_version"]; summaryOnly {
		var summary struct {
			Passed         int    `json:"passed"`
			Failed         int    `json:"failed"`
			Skipped        int    `json:"skipped"`
			ParsingErrors  int    `json:"parsing_errors"`
			ResourceCount  int    `json:"resource_count"`
			CheckovVersion string `json:"checkov_version"`
		}
		if err := decodeStrictJSON(trimmed, &summary); err != nil {
			return 0, err
		}
		if summary.Passed < 0 || summary.Failed < 0 || summary.Skipped < 0 || summary.ParsingErrors < 0 || summary.ResourceCount < 0 || strings.TrimSpace(summary.CheckovVersion) == "" {
			return 0, errors.New("invalid Checkov summary")
		}
		if summary.ParsingErrors != 0 {
			return 0, fmt.Errorf("checkov summary contains %d parsing errors", summary.ParsingErrors)
		}
		return summary.Failed, nil
	}
	var report checkovReport
	if err := decodeStrictJSON(trimmed, &report); err != nil {
		return 0, err
	}
	return countCheckovReports([]checkovReport{report})
}

type checkovReport struct {
	CheckType string          `json:"check_type"`
	Results   *checkovResults `json:"results"`
	Summary   json.RawMessage `json:"summary"`
	URL       string          `json:"url,omitempty"`
	Comment   string          `json:"comment,omitempty"`
}

type checkovResults struct {
	PassedChecks  []json.RawMessage  `json:"passed_checks"`
	FailedChecks  *[]json.RawMessage `json:"failed_checks"`
	SkippedChecks []json.RawMessage  `json:"skipped_checks"`
	ParsingErrors *[]json.RawMessage `json:"parsing_errors"`
}

func countCheckovReports(reports []checkovReport) (int, error) {
	findings := 0
	for index, report := range reports {
		if report.Results == nil {
			return 0, fmt.Errorf("checkov report %d has no results", index)
		}
		if err := requireJSONObject(report.Summary, "checkov summary"); err != nil {
			return 0, fmt.Errorf("report %d: %w", index, err)
		}
		if report.Results.FailedChecks == nil {
			return 0, fmt.Errorf("checkov report %d has no failed_checks array", index)
		}
		if report.Results.ParsingErrors == nil {
			return 0, fmt.Errorf("checkov report %d has no parsing_errors array", index)
		}
		if len(*report.Results.ParsingErrors) != 0 {
			return 0, fmt.Errorf("checkov report %d contains %d parsing errors", index, len(*report.Results.ParsingErrors))
		}
		if err := validateObjects(*report.Results.FailedChecks, "Checkov failed check"); err != nil {
			return 0, err
		}
		findings += len(*report.Results.FailedChecks)
	}
	return findings, nil
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("report contains a trailing JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func validateObjects(values []json.RawMessage, label string) error {
	for index, value := range values {
		if err := requireJSONObject(value, label); err != nil {
			return fmt.Errorf("%s %d: %w", label, index, err)
		}
	}
	return nil
}

func requireJSONObject(raw json.RawMessage, label string) error {
	object, err := decodeJSONObject(raw, label)
	if err != nil {
		return err
	}
	if len(object) == 0 {
		return fmt.Errorf("%s must not be empty", label)
	}
	return nil
}

func requireJSONObjectAllowEmpty(raw json.RawMessage, label string) error {
	_, err := decodeJSONObject(raw, label)
	return err
}

func decodeJSONObject(raw json.RawMessage, label string) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%s must be a JSON object", label)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return object, nil
}
