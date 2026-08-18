package evidence

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadRejectsMalformedEvidence(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{name: "empty", json: "", want: "empty evidence"},
		{name: "unknown field", json: evidenceJSON(t, validRecord(), `,"unknown":true`), want: "unknown field"},
		{name: "truncated", json: `{"schema_version":"1"`, want: "decode evidence"},
		{name: "trailing value", json: evidenceJSON(t, validRecord(), "") + "{}", want: "trailing"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(test.json))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Read() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestWriteAtomicRoundTripIsDeterministic(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "evidence.json")
	if err := WriteAtomic(filename, validRecord()); err != nil {
		t.Fatalf("WriteAtomic() error = %v", err)
	}
	first, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read first write: %v", err)
	}

	record, err := Read(bytes.NewReader(first))
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if record.Identity() != validRecord().Identity() {
		t.Fatalf("record identity = %q", record.Identity())
	}

	if err := WriteAtomic(filename, validRecord()); err != nil {
		t.Fatalf("second WriteAtomic() error = %v", err)
	}
	second, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read second write: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("writes differ:\nfirst:  %s\nsecond: %s", first, second)
	}
	if entries, err := filepath.Glob(filepath.Join(directory, ".evidence.json-*")); err != nil || len(entries) != 0 {
		t.Fatalf("temporary files after write = %v, error = %v", entries, err)
	}
}

func TestWriteAtomicFailureLeavesNoPartialFile(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "evidence.json")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatalf("create destination directory: %v", err)
	}

	err := WriteAtomic(destination, validRecord())
	if err == nil {
		t.Fatal("WriteAtomic() succeeded when rename destination was a directory")
	}
	info, statErr := os.Stat(destination)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("destination changed after failure: info = %v, error = %v", info, statErr)
	}
	entries, globErr := filepath.Glob(filepath.Join(directory, ".evidence.json-*"))
	if globErr != nil || len(entries) != 0 {
		t.Fatalf("temporary files after failed write = %v, error = %v", entries, globErr)
	}
}

func evidenceJSON(t *testing.T, record Record, beforeClose string) string {
	t.Helper()
	data, err := record.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return strings.TrimSuffix(string(data), "}") + beforeClose + "}"
}
