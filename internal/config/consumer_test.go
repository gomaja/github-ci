package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestConsumerAcceptsExactCollectionLimits(t *testing.T) {
	generated := make([]string, maxGeneratedPaths)
	modules := make([]GoModule, maxModules)
	for index := range generated {
		generated[index] = fmt.Sprintf("generated/path%d", index)
	}
	for index := range modules {
		modules[index].Path = Module(fmt.Sprintf("module%d", index))
	}
	consumer := Consumer{
		SchemaVersion:  schemaVersion,
		Profile:        ProfileGoStrict,
		Go:             &Go{Modules: modules},
		GeneratedPaths: generated,
	}
	if err := consumer.Validate(); err != nil {
		t.Fatalf("Validate() at exact collection limits error = %v", err)
	}
}

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
	if consumer.SchemaVersion != 2 {
		t.Fatalf("SchemaVersion = %d, want 2", consumer.SchemaVersion)
	}
	if consumer.Profile != "go-strict" {
		t.Fatalf("Profile = %q, want go-strict", consumer.Profile)
	}
	if consumer.Go == nil || len(consumer.Go.Modules) != 2 {
		t.Fatalf("Go modules = %v, want two modules", consumer.Go)
	}
}

func TestDecodeConsumerRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "empty", yaml: "", want: "empty configuration"},
		{name: "unknown field", yaml: "schema-version: 2\nprofile: go-strict\nunknown: true\n", want: "field unknown not found"},
		{name: "duplicate key", yaml: "schema-version: 2\nschema-version: 2\nprofile: go-strict\n", want: "already defined"},
		{name: "two documents", yaml: "schema-version: 2\nprofile: go-strict\n---\nschema-version: 2\nprofile: go-strict\n", want: "multiple YAML documents"},
		{name: "schema version", yaml: "schema-version: 1\nprofile: go-strict\n", want: "schema-version"},
		{name: "traversal module", yaml: "schema-version: 2\nprofile: go-strict\ngo:\n  modules:\n    - path: ../outside\n", want: "traversal"},
		{name: "absolute module", yaml: "schema-version: 2\nprofile: go-strict\ngo:\n  modules:\n    - path: /tmp/module\n", want: "absolute"},
		{name: "backslash module", yaml: "schema-version: 2\nprofile: go-strict\ngo:\n  modules:\n    - path: 'src\\pkg'\n", want: "slash-separated"},
		{name: "unknown profile", yaml: "schema-version: 2\nprofile: permissive\n", want: "unsupported profile"},
		{name: "control character", yaml: "schema-version: 2\nprofile: go-strict\nexceptions: \"bad\\u0007path\"\n", want: "control character"},
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

func TestConsumerValidationDoesNotStopAtValidCollectionEntries(t *testing.T) {
	tests := []struct {
		name     string
		consumer Consumer
		want     string
	}{
		{
			name: "valid generated path before invalid exceptions path",
			consumer: Consumer{
				SchemaVersion: 2, Profile: ProfileGoStrict,
				GeneratedPaths: []string{"generated"}, Exceptions: "../outside",
			},
			want: "traversal",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.consumer.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
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

func TestSchemaTimeoutPatternsMatchRuntimeValidation(t *testing.T) {
	for _, schemaFile := range []string{
		"../../schemas/consumer.schema.json",
		"../../schemas/governance.schema.json",
	} {
		t.Run(schemaFile, func(t *testing.T) {
			patterns := schemaTimeoutPatterns(t, schemaFile)
			for definition, pattern := range patterns {
				if pattern != testTimeoutSchemaPattern {
					t.Errorf("%s timeout pattern = %q, want runtime pattern", definition, pattern)
				}
			}
		})
	}

	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "1s", want: true}, {value: "59s", want: true}, {value: "60s", want: true},
		{value: "999s", want: true}, {value: "1000s", want: true}, {value: "2699s", want: true},
		{value: "2700s", want: true}, {value: "1m", want: true}, {value: "39m", want: true},
		{value: "45m", want: true}, {value: "0s"}, {value: "2701s"}, {value: "46m"},
		{value: "1h"}, {value: "1m30s"}, {value: "500ms"}, {value: "soon"}, {value: "-1s"},
	} {
		t.Run(test.value, func(t *testing.T) {
			timeout := test.value
			runtimeValid := (GoSettings{TestTimeout: &timeout}).validate("test") == nil
			if schemaValid := testTimeoutPattern.MatchString(test.value); schemaValid != test.want || runtimeValid != test.want {
				t.Fatalf("timeout %q schema-valid=%t runtime-valid=%t, want %t", test.value, schemaValid, runtimeValid, test.want)
			}
		})
	}
}

func TestModuleSchemasRejectExplicitEmptyAndExactDuplicates(t *testing.T) {
	for _, schemaFile := range []string{
		"../../schemas/consumer.schema.json",
		"../../schemas/governance.schema.json",
	} {
		t.Run(schemaFile, func(t *testing.T) {
			data, err := os.ReadFile(schemaFile)
			if err != nil {
				t.Fatalf("read schema %q: %v", schemaFile, err)
			}
			var schema struct {
				Definitions map[string]struct {
					Properties map[string]struct {
						MinItems    int  `json:"minItems"`
						UniqueItems bool `json:"uniqueItems"`
					} `json:"properties"`
				} `json:"$defs"`
			}
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatalf("unmarshal schema %q: %v", schemaFile, err)
			}
			modules := schema.Definitions["go"].Properties["modules"]
			if modules.MinItems != 1 || !modules.UniqueItems {
				t.Fatalf("schema %q modules minItems=%d uniqueItems=%t, want 1 and true", schemaFile, modules.MinItems, modules.UniqueItems)
			}
		})
	}
}

func schemaTimeoutPatterns(t *testing.T, filename string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read schema %q: %v", filename, err)
	}
	var schema struct {
		Definitions map[string]struct {
			Properties map[string]struct {
				Pattern string `json:"pattern"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("unmarshal schema %q: %v", filename, err)
	}
	patterns := map[string]string{}
	for _, definition := range []string{"go-settings", "go-module"} {
		pattern := schema.Definitions[definition].Properties["test-timeout"].Pattern
		if pattern == "" {
			t.Fatalf("schema %q definition %q has no test-timeout pattern", filename, definition)
		}
		patterns[definition] = pattern
	}
	return patterns
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
