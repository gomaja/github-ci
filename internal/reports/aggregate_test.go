package reports

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteAggregateRoundTrip(t *testing.T) {
	reports := []NamedReport{
		{Module: "module-a", Data: []byte(`{"schema_version":"1","execution_successful":true}`)},
		{Module: "module-b", Data: []byte(`{"schema_version":"1","execution_successful":false}`)},
	}
	var output bytes.Buffer
	if err := WriteAggregate("command-status", reports, &output); err != nil {
		t.Fatalf("WriteAggregate() error = %v", err)
	}
	result, err := Count("command-status", bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatalf("Count(aggregate) error = %v", err)
	}
	if result.Findings != 1 {
		t.Fatalf("Count(aggregate) findings = %d, want 1", result.Findings)
	}

	var second bytes.Buffer
	if err := WriteAggregate("command-status", reports, &second); err != nil {
		t.Fatalf("second WriteAggregate() error = %v", err)
	}
	if !bytes.Equal(output.Bytes(), second.Bytes()) {
		t.Fatal("aggregate output is not deterministic")
	}
}

func TestWriteAggregateRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		reports []NamedReport
		want    string
	}{
		{name: "unknown tool", tool: "unknown", reports: []NamedReport{{Module: ".", Data: []byte("{}")}}, want: "unsupported"},
		{name: "empty", tool: "command-status", want: "at least one"},
		{name: "unsafe module", tool: "command-status", reports: []NamedReport{{Module: "../outside", Data: []byte("{}")}}, want: "traversal"},
		{name: "duplicate module", tool: "command-status", reports: []NamedReport{{Module: ".", Data: []byte(`{"schema_version":"1","execution_successful":true}`)}, {Module: ".", Data: []byte(`{"schema_version":"1","execution_successful":false}`)}}, want: "duplicate"},
		{name: "empty payload", tool: "command-status", reports: []NamedReport{{Module: "."}}, want: "empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := WriteAggregate(test.tool, test.reports, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("WriteAggregate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCountRejectsTamperedAggregate(t *testing.T) {
	var output bytes.Buffer
	if err := WriteAggregate("command-status", []NamedReport{{Module: ".", Data: []byte(`{"schema_version":"1","execution_successful":true}`)}}, &output); err != nil {
		t.Fatalf("WriteAggregate() error = %v", err)
	}
	tampered := strings.Replace(output.String(), "c3VjY2Vzc2Z1bCIsInRydWU", "c3VjY2Vzc2Z1bCIsImZhbHNl", 1)
	if tampered == output.String() {
		// The exact base64 is intentionally opaque; changing the declared digest is sufficient.
		tampered = strings.Replace(output.String(), "sha256:", "sha256:0", 1)
	}
	if _, err := Count("command-status", strings.NewReader(tampered)); err == nil {
		t.Fatal("Count() accepted tampered aggregate")
	}
}
