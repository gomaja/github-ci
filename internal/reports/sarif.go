package reports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type sarifLog struct {
	Version                  string             `json:"version"`
	Schema                   string             `json:"$schema,omitempty"`
	Runs                     *[]json.RawMessage `json:"runs"`
	InlineExternalProperties json.RawMessage    `json:"inlineExternalProperties,omitempty"`
	Properties               json.RawMessage    `json:"properties,omitempty"`
}

func countSARIF(data []byte) (int, error) {
	var log sarifLog
	if err := decodeStrictJSON(data, &log); err != nil {
		return 0, err
	}
	if err := validateSARIFLog(log); err != nil {
		return 0, err
	}

	identities := make(map[string]struct{})
	findings := 0
	for runIndex, rawRun := range *log.Runs {
		count, err := countSARIFRun(rawRun, runIndex, identities)
		if err != nil {
			return 0, err
		}
		findings += count
	}
	return findings, nil
}

func validateSARIFLog(log sarifLog) error {
	if log.Version != "2.1.0" {
		return fmt.Errorf("unsupported SARIF version %q", log.Version)
	}
	// OASIS SARIF 2.1.0 + Errata 01 §3.13.5: externalized properties are unsupported here.
	if log.InlineExternalProperties != nil {
		return errors.New("SARIF inlineExternalProperties are unsupported")
	}
	if log.Properties != nil {
		if err := requireJSONObjectAllowEmpty(log.Properties, "SARIF root properties"); err != nil {
			return err
		}
	}
	// §3.13.4 permits null or empty runs for producers without run data. This evidence
	// parser requires at least one completed scanner run, so neither is a clean report.
	if log.Runs == nil || len(*log.Runs) == 0 {
		return errors.New("SARIF report has no runs")
	}
	return nil
}

func countSARIFRun(raw json.RawMessage, runIndex int, identities map[string]struct{}) (int, error) {
	var run map[string]json.RawMessage
	if err := json.Unmarshal(raw, &run); err != nil {
		return 0, fmt.Errorf("decode SARIF run %d: %w", runIndex, err)
	}
	if len(run) == 0 {
		return 0, fmt.Errorf("SARIF run %d is empty", runIndex)
	}
	if err := requireJSONObject(run["tool"], "SARIF run tool"); err != nil {
		return 0, fmt.Errorf("run %d: %w", runIndex, err)
	}
	// OASIS SARIF 2.1.0 + Errata 01 §3.18.2 requires every tool object to have a driver.
	resolver, err := newSARIFNotificationResolver(run["tool"])
	if err != nil {
		return 0, fmt.Errorf("SARIF run %d tool: %w", runIndex, err)
	}
	// OASIS SARIF 2.1.0 + Errata 01 §3.14.2: do not silently omit external report data.
	if _, exists := run["externalPropertyFileReferences"]; exists {
		return 0, fmt.Errorf("SARIF run %d externalPropertyFileReferences are unsupported", runIndex)
	}
	// OASIS SARIF 2.1.0 + Errata 01 §3.14.11 defines the run's invocation array.
	if invocationsRaw, exists := run["invocations"]; exists {
		if err := validateSARIFInvocations(invocationsRaw, resolver); err != nil {
			return 0, fmt.Errorf("SARIF run %d: %w", runIndex, err)
		}
	}
	return countSARIFResults(run["results"], runIndex, identities)
}

func countSARIFResults(raw json.RawMessage, runIndex int, identities map[string]struct{}) (int, error) {
	if raw == nil {
		return 0, nil
	}
	var results []json.RawMessage
	if err := json.Unmarshal(raw, &results); err != nil {
		return 0, fmt.Errorf("decode SARIF run %d results: %w", runIndex, err)
	}
	if results == nil {
		return 0, fmt.Errorf("SARIF run %d results must be an array", runIndex)
	}
	for resultIndex, rawResult := range results {
		if err := indexSARIFResult(rawResult, runIndex, resultIndex, identities); err != nil {
			return 0, err
		}
	}
	return len(results), nil
}

func indexSARIFResult(raw json.RawMessage, runIndex, resultIndex int, identities map[string]struct{}) error {
	if err := requireJSONObject(raw, "SARIF result"); err != nil {
		return fmt.Errorf("run %d result %d: %w", runIndex, resultIndex, err)
	}
	identity, err := sarifResultIdentity(raw)
	if err != nil {
		return fmt.Errorf("canonicalize SARIF run %d result %d: %w", runIndex, resultIndex, err)
	}
	if _, exists := identities[identity]; exists {
		return fmt.Errorf("duplicate SARIF result in run %d at index %d", runIndex, resultIndex)
	}
	identities[identity] = struct{}{}
	return nil
}

func validateSARIFInvocations(raw json.RawMessage, resolver *sarifNotificationResolver) error {
	var invocations []json.RawMessage
	if err := json.Unmarshal(raw, &invocations); err != nil {
		return fmt.Errorf("decode invocations: %w", err)
	}
	if invocations == nil {
		return errors.New("invocations must be an array")
	}
	for index, rawInvocation := range invocations {
		var invocation map[string]json.RawMessage
		if err := json.Unmarshal(rawInvocation, &invocation); err != nil || invocation == nil {
			return fmt.Errorf("invocation %d must be a JSON object", index)
		}
		// OASIS SARIF 2.1.0 + Errata 01 §3.20.14 requires explicit execution success.
		successRaw, exists := invocation["executionSuccessful"]
		if !exists {
			return fmt.Errorf("invocation %d has no executionSuccessful property", index)
		}
		var successful bool
		if err := json.Unmarshal(successRaw, &successful); err != nil {
			return fmt.Errorf("invocation %d executionSuccessful must be boolean", index)
		}
		if !successful {
			return fmt.Errorf("invocation %d executionSuccessful is false", index)
		}
		overrides, err := resolver.notificationOverrides(invocation)
		if err != nil {
			return fmt.Errorf("invocation %d: %w", index, err)
		}
		// OASIS SARIF 2.1.0 + Errata 01 §3.20.21: an error notification fails the run.
		if err := resolver.rejectErrorNotifications(invocation, "toolExecutionNotifications", overrides); err != nil {
			return fmt.Errorf("invocation %d: %w", index, err)
		}
		// OASIS SARIF 2.1.0 + Errata 01 §3.20.22 applies the same rule to configuration.
		if err := resolver.rejectErrorNotifications(invocation, "toolConfigurationNotifications", overrides); err != nil {
			return fmt.Errorf("invocation %d: %w", index, err)
		}
	}
	return nil
}

func sarifResultIdentity(raw json.RawMessage) (string, error) {
	var result struct {
		RuleID              string            `json:"ruleId,omitempty"`
		Fingerprints        map[string]string `json:"fingerprints,omitempty"`
		PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", err
	}
	if len(result.Fingerprints) == 0 && len(result.PartialFingerprints) == 0 {
		return canonicalJSON(raw)
	}
	identity, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(identity), nil
}

func canonicalJSON(raw json.RawMessage) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}
