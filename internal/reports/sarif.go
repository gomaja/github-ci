package reports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type sarifLog struct {
	Version                  string            `json:"version"`
	Schema                   string            `json:"$schema,omitempty"`
	Runs                     []json.RawMessage `json:"runs"`
	InlineExternalProperties []json.RawMessage `json:"inlineExternalProperties,omitempty"`
}

func countSARIF(data []byte) (int, error) {
	var log sarifLog
	if err := decodeStrictJSON(data, &log); err != nil {
		return 0, err
	}
	if log.Version != "2.1.0" {
		return 0, fmt.Errorf("unsupported SARIF version %q", log.Version)
	}
	if len(log.Runs) == 0 {
		return 0, errors.New("SARIF report has no runs")
	}

	identities := make(map[string]struct{})
	findings := 0
	for runIndex, rawRun := range log.Runs {
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
