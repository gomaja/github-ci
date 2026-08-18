package reports

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/gomaja/github-ci/internal/pathpolicy"
)

const aggregateSchemaVersion = "1"

var aggregateSchemaKey = []byte(`"aggregate_schema_version"`)

// NamedReport is one module-scoped native analyzer report.
type NamedReport struct {
	Module string
	Data   []byte
}

type aggregateDocument struct {
	SchemaVersion string          `json:"aggregate_schema_version"`
	ParserTool    string          `json:"parser_tool"`
	Reports       []aggregateWire `json:"reports"`
}

type aggregateWire struct {
	Module  string `json:"module"`
	SHA256  string `json:"sha256"`
	Payload string `json:"payload_base64"`
}

// WriteAggregate validates and combines sorted per-module native reports.
func WriteAggregate(tool string, named []NamedReport, writer io.Writer) error {
	if !IsSupported(tool) {
		return fmt.Errorf("unsupported report tool %q", tool)
	}
	if writer == nil {
		return errors.New("aggregate writer is nil")
	}
	if len(named) == 0 {
		return errors.New("aggregate requires at least one native report")
	}
	reports := slices.Clone(named)
	slices.SortFunc(reports, func(left, right NamedReport) int { return strings.Compare(left.Module, right.Module) })
	document := aggregateDocument{SchemaVersion: aggregateSchemaVersion, ParserTool: tool, Reports: make([]aggregateWire, 0, len(reports))}
	previous := ""
	for index, report := range reports {
		if err := pathpolicy.Validate("aggregate module", report.Module); err != nil {
			return fmt.Errorf("report %d: %w", index, err)
		}
		if index > 0 && report.Module == previous {
			return fmt.Errorf("duplicate aggregate module %q", report.Module)
		}
		previous = report.Module
		if len(bytes.TrimSpace(report.Data)) == 0 {
			return fmt.Errorf("aggregate module %q has an empty report", report.Module)
		}
		if isAggregate(report.Data) {
			return fmt.Errorf("aggregate module %q contains a nested aggregate", report.Module)
		}
		if _, err := parsers[tool](report.Data); err != nil {
			return fmt.Errorf("aggregate module %q: %w", report.Module, err)
		}
		document.Reports = append(document.Reports, aggregateWire{
			Module: report.Module, SHA256: reportDigest(report.Data),
			Payload: base64.StdEncoding.EncodeToString(report.Data),
		})
	}
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("marshal aggregate: %w", err)
	}
	if len(data)+1 > MaxInputBytes {
		return fmt.Errorf("aggregate exceeds %d byte limit", MaxInputBytes)
	}
	data = append(data, '\n')
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("write aggregate: %w", err)
	}
	return nil
}

func isAggregate(data []byte) bool {
	if !bytes.Contains(data, aggregateSchemaKey) {
		return false
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(data, &probe) != nil {
		return false
	}
	_, exists := probe["aggregate_schema_version"]
	return exists
}

func countAggregate(tool string, data []byte) (int, error) {
	var document aggregateDocument
	if err := decodeStrictJSON(data, &document); err != nil {
		return 0, fmt.Errorf("decode aggregate: %w", err)
	}
	if document.SchemaVersion != aggregateSchemaVersion {
		return 0, fmt.Errorf("unsupported aggregate schema %q", document.SchemaVersion)
	}
	if document.ParserTool != tool {
		return 0, fmt.Errorf("aggregate parser %q does not match %q", document.ParserTool, tool)
	}
	if len(document.Reports) == 0 {
		return 0, errors.New("aggregate has no reports")
	}
	findings := 0
	previous := ""
	for index, report := range document.Reports {
		if err := pathpolicy.Validate("aggregate module", report.Module); err != nil {
			return 0, fmt.Errorf("report %d: %w", index, err)
		}
		if index > 0 && strings.Compare(previous, report.Module) >= 0 {
			return 0, errors.New("aggregate reports must be sorted with unique modules")
		}
		previous = report.Module
		payload, err := base64.StdEncoding.Strict().DecodeString(report.Payload)
		if err != nil {
			return 0, fmt.Errorf("report %d payload: %w", index, err)
		}
		if len(bytes.TrimSpace(payload)) == 0 {
			return 0, fmt.Errorf("report %d payload is empty", index)
		}
		if report.SHA256 != reportDigest(payload) {
			return 0, fmt.Errorf("report %d digest mismatch", index)
		}
		if isAggregate(payload) {
			return 0, fmt.Errorf("report %d is a nested aggregate", index)
		}
		count, err := parsers[tool](payload)
		if err != nil {
			return 0, fmt.Errorf("report %d: %w", index, err)
		}
		if count > int(^uint(0)>>1)-findings {
			return 0, errors.New("aggregate finding count overflow")
		}
		findings += count
	}
	return findings, nil
}

func reportDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", digest)
}
