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
	if log.Version != "2.1.0" {
		return 0, fmt.Errorf("unsupported SARIF version %q", log.Version)
	}
	// OASIS SARIF 2.1.0 + Errata 01 §3.13.5: externalized properties are unsupported here.
	if log.InlineExternalProperties != nil {
		return 0, errors.New("SARIF inlineExternalProperties are unsupported")
	}
	if log.Properties != nil {
		if err := requireJSONObjectAllowEmpty(log.Properties, "SARIF root properties"); err != nil {
			return 0, err
		}
	}
	if log.Runs == nil || len(*log.Runs) == 0 {
		return 0, errors.New("SARIF report has no runs")
	}

	identities := make(map[string]struct{})
	findings := 0
	for runIndex, rawRun := range *log.Runs {
		var run map[string]json.RawMessage
		if err := json.Unmarshal(rawRun, &run); err != nil {
			return 0, fmt.Errorf("decode SARIF run %d: %w", runIndex, err)
		}
		if len(run) == 0 {
			return 0, fmt.Errorf("SARIF run %d is empty", runIndex)
		}
		if err := requireJSONObject(run["tool"], "SARIF run tool"); err != nil {
			return 0, fmt.Errorf("run %d: %w", runIndex, err)
		}
		// OASIS SARIF 2.1.0 + Errata 01 §3.14.2: do not silently omit external report data.
		if _, exists := run["externalPropertyFileReferences"]; exists {
			return 0, fmt.Errorf("SARIF run %d externalPropertyFileReferences are unsupported", runIndex)
		}
		// OASIS SARIF 2.1.0 + Errata 01 §3.14.11 defines the run's invocation array.
		if invocationsRaw, exists := run["invocations"]; exists {
			if err := validateSARIFInvocations(invocationsRaw); err != nil {
				return 0, fmt.Errorf("SARIF run %d: %w", runIndex, err)
			}
		}
		resultsRaw, exists := run["results"]
		if !exists {
			continue
		}
		var results []json.RawMessage
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			return 0, fmt.Errorf("decode SARIF run %d results: %w", runIndex, err)
		}
		if results == nil {
			return 0, fmt.Errorf("SARIF run %d results must be an array", runIndex)
		}
		for resultIndex, rawResult := range results {
			if err := requireJSONObject(rawResult, "SARIF result"); err != nil {
				return 0, fmt.Errorf("run %d result %d: %w", runIndex, resultIndex, err)
			}
			identity, err := sarifResultIdentity(rawResult)
			if err != nil {
				return 0, fmt.Errorf("canonicalize SARIF run %d result %d: %w", runIndex, resultIndex, err)
			}
			if _, exists := identities[identity]; exists {
				return 0, fmt.Errorf("duplicate SARIF result in run %d at index %d", runIndex, resultIndex)
			}
			identities[identity] = struct{}{}
			findings++
		}
	}
	return findings, nil
}

func validateSARIFInvocations(raw json.RawMessage) error {
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
		// OASIS SARIF 2.1.0 + Errata 01 §3.20.21: an error notification fails the run.
		if err := rejectSARIFErrorNotifications(invocation, "toolExecutionNotifications"); err != nil {
			return fmt.Errorf("invocation %d: %w", index, err)
		}
		// OASIS SARIF 2.1.0 + Errata 01 §3.20.22 applies the same rule to configuration.
		if err := rejectSARIFErrorNotifications(invocation, "toolConfigurationNotifications"); err != nil {
			return fmt.Errorf("invocation %d: %w", index, err)
		}
	}
	return nil
}

func rejectSARIFErrorNotifications(invocation map[string]json.RawMessage, property string) error {
	raw, exists := invocation[property]
	if !exists {
		return nil
	}
	var notifications []json.RawMessage
	if err := json.Unmarshal(raw, &notifications); err != nil {
		return fmt.Errorf("decode %s: %w", property, err)
	}
	if notifications == nil {
		return fmt.Errorf("%s must be an array", property)
	}
	for index, rawNotification := range notifications {
		var notification map[string]json.RawMessage
		if err := json.Unmarshal(rawNotification, &notification); err != nil || notification == nil {
			return fmt.Errorf("%s[%d] must be a JSON object", property, index)
		}
		level := "warning"
		if rawLevel, exists := notification["level"]; exists {
			if err := json.Unmarshal(rawLevel, &level); err != nil {
				return fmt.Errorf("%s[%d].level must be a string", property, index)
			}
		}
		switch level {
		case "none", "note", "warning":
		case "error":
			return fmt.Errorf("%s[%d] has level error", property, index)
		default:
			return fmt.Errorf("%s[%d] has unsupported level %q", property, index, level)
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
