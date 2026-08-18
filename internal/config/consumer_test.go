package config

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDecodeConsumer(t *testing.T) {
	valid, err := os.Open("../../testdata/config/consumer-valid.yaml")
	if err != nil {
		t.Fatalf("open valid fixture: %v", err)
	}
	t.Cleanup(func() { _ = valid.Close() })

	consumer, err := DecodeConsumer(valid)
	if err != nil {
		t.Fatalf("DecodeConsumer() error = %v", err)
	}
	if consumer.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1", consumer.SchemaVersion)
	}
	if consumer.Profile != "go-strict" {
		t.Fatalf("Profile = %q, want go-strict", consumer.Profile)
	}
	if len(consumer.Modules) != 2 {
		t.Fatalf("Modules = %v, want two modules", consumer.Modules)
	}
}

func TestDecodeConsumerRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "empty", yaml: "", want: "empty configuration"},
		{name: "unknown field", yaml: "schema-version: 1\nprofile: go-strict\nunknown: true\n", want: "field unknown not found"},
		{name: "duplicate key", yaml: "schema-version: 1\nschema-version: 1\nprofile: go-strict\n", want: "already defined"},
		{name: "two documents", yaml: "schema-version: 1\nprofile: go-strict\n---\nschema-version: 1\nprofile: go-strict\n", want: "multiple YAML documents"},
		{name: "schema version", yaml: "schema-version: 2\nprofile: go-strict\n", want: "schema-version"},
		{name: "traversal module", yaml: "schema-version: 1\nprofile: go-strict\nmodules: [../outside]\n", want: "traversal"},
		{name: "absolute module", yaml: "schema-version: 1\nprofile: go-strict\nmodules: [/tmp/module]\n", want: "absolute"},
		{name: "backslash module", yaml: "schema-version: 1\nprofile: go-strict\nmodules: ['src\\pkg']\n", want: "slash-separated"},
		{name: "duplicate module", yaml: "schema-version: 1\nprofile: go-strict\nmodules: [api, api]\n", want: "duplicate module"},
		{name: "unknown profile", yaml: "schema-version: 1\nprofile: permissive\n", want: "unsupported profile"},
		{name: "unsupported service", yaml: "schema-version: 1\nprofile: go-strict\nservices: [mysql]\n", want: "unsupported service"},
		{name: "control character", yaml: "schema-version: 1\nprofile: go-strict\nexceptions: \"bad\\u0007path\"\n", want: "control character"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeConsumer(strings.NewReader(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("DecodeConsumer() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestConsumerSchemaIsValidJSON(t *testing.T) {
	data, err := os.ReadFile("../../schemas/consumer.schema.json")
	if err != nil {
		t.Fatalf("read consumer schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("unmarshal consumer schema: %v", err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema = %v", schema["$schema"])
	}
}

func TestSchemaPathPatternsMatchRuntimeRejections(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: ".", want: true},
		{path: "internal/config", want: true},
		{path: ".github/github-ci-exceptions.yaml", want: true},
		{path: "/abs", want: false},
		{path: "C:/repo", want: false},
		{path: `C:\repo`, want: false},
		{path: "../outside", want: false},
		{path: "internal/../outside", want: false},
		{path: `internal\config`, want: false},
	}

	for _, schemaFile := range []string{
		"../../schemas/consumer.schema.json",
		"../../schemas/governance.schema.json",
	} {
		t.Run(schemaFile, func(t *testing.T) {
			pattern := schemaPathPattern(t, schemaFile)
			matcher, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatalf("compile path pattern %q: %v", pattern, err)
			}
			for _, test := range tests {
				if got := matcher.MatchString(test.path); got != test.want {
					t.Errorf("path pattern match for %q = %t, want %t", test.path, got, test.want)
				}
			}
		})
	}
}

func schemaPathPattern(t *testing.T, filename string) string {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read schema %q: %v", filename, err)
	}
	var schema struct {
		Definitions map[string]struct {
			Pattern string `json:"pattern"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("unmarshal schema %q: %v", filename, err)
	}
	if schema.Definitions["path"].Pattern == "" {
		t.Fatalf("schema %q has no path pattern", filename)
	}
	return schema.Definitions["path"].Pattern
}
