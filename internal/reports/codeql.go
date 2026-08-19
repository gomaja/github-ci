package reports

import (
	"bytes"
	"encoding/json"
)

const codeQLEmptyNotificationText = "CodeQL emitted an empty diagnostic message."

// OASIS SARIF 2.1.0 + Errata 01 section 3.11.8 requires message.text to be
// non-empty when present. CodeQL 4.37.7 can emit an empty diagnostic text, so
// repair only that producer defect while preserving the raw report as evidence.
func normalizeCodeQLEmptyNotificationText(data []byte) []byte {
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil {
		return data
	}
	var runs []map[string]json.RawMessage
	if json.Unmarshal(root["runs"], &runs) != nil {
		return data
	}
	changed := false
	for _, run := range runs {
		if normalizeCodeQLRun(run) {
			changed = true
		}
	}
	if !changed {
		return data
	}
	encodedRuns, err := json.Marshal(runs)
	if err != nil {
		return data
	}
	root["runs"] = encodedRuns
	encoded, err := json.Marshal(root)
	if err != nil {
		return data
	}
	return encoded
}

func normalizeCodeQLRun(run map[string]json.RawMessage) bool {
	var invocations []map[string]json.RawMessage
	if json.Unmarshal(run["invocations"], &invocations) != nil {
		return false
	}
	changed := false
	for _, invocation := range invocations {
		for _, property := range []string{"toolExecutionNotifications", "toolConfigurationNotifications"} {
			if normalizeCodeQLNotifications(invocation, property) {
				changed = true
			}
		}
	}
	encoded, err := json.Marshal(invocations)
	if err != nil {
		return false
	}
	run["invocations"] = encoded
	return changed
}

func normalizeCodeQLNotifications(invocation map[string]json.RawMessage, property string) bool {
	raw, exists := invocation[property]
	if !exists {
		return false
	}
	var notifications []map[string]json.RawMessage
	if json.Unmarshal(raw, &notifications) != nil {
		return false
	}
	changed := false
	for _, notification := range notifications {
		if normalizeCodeQLNotification(notification) {
			changed = true
		}
	}
	if !changed {
		return false
	}
	encoded, err := json.Marshal(notifications)
	if err != nil {
		return false
	}
	invocation[property] = encoded
	return true
}

func normalizeCodeQLNotification(notification map[string]json.RawMessage) bool {
	var message map[string]json.RawMessage
	if json.Unmarshal(notification["message"], &message) != nil {
		return false
	}
	if !bytes.Equal(bytes.TrimSpace(message["text"]), []byte(`""`)) {
		return false
	}
	message["text"] = json.RawMessage(`"` + codeQLEmptyNotificationText + `"`)
	encoded, err := json.Marshal(message)
	if err != nil {
		return false
	}
	notification["message"] = encoded
	return true
}
