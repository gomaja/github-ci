package pathpolicy

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: ".", want: true},
		{path: "internal/config", want: true},
		{path: ".github/github-ci.yaml", want: true},
		{path: "a.b/c-d_1", want: true},
		{path: "", want: false},
		{path: "/absolute", want: false},
		{path: `C:\absolute`, want: false},
		{path: "../outside", want: false},
		{path: "internal/../outside", want: false},
		{path: `internal\config`, want: false},
		{path: "internal//config", want: false},
		{path: "with space", want: false},
		{path: "unicode/é", want: false},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			if got := Validate("path", test.path) == nil; got != test.want {
				t.Fatalf("Validate(%q) success = %t, want %t", test.path, got, test.want)
			}
		})
	}
}

func TestValidateClassifiesEveryAbsolutePathForm(t *testing.T) {
	for _, value := range []string{"/absolute", `\server\share`, "C:/absolute"} {
		t.Run(value, func(t *testing.T) {
			err := Validate("path", value)
			if err == nil || !strings.Contains(err.Error(), "must be relative, not absolute") {
				t.Fatalf("Validate(%q) error = %v", value, err)
			}
		})
	}
}

func TestWindowsAbsolutePathRequiresEveryComponent(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "C:/", want: true},
		{value: `z:\`, want: true},
		{value: "C:", want: false},
		{value: "1:/", want: false},
		{value: "C-/", want: false},
		{value: "C:a", want: false},
		{value: "C::", want: false},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			if got := windowsAbsolutePath(test.value); got != test.want {
				t.Fatalf("windowsAbsolutePath(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestSchemaPatternMatchesRuntimeAndAllSchemas(t *testing.T) {
	matcher := regexp.MustCompile(SchemaPattern)
	for _, value := range []string{".", "internal/config", ".github/workflows/ci.yml", "/abs", "../outside", `a\b`, "a//b", "with space"} {
		if got, want := matcher.MatchString(value), Validate("path", value) == nil; got != want {
			t.Errorf("SchemaPattern match for %q = %t, runtime = %t", value, got, want)
		}
	}

	for _, schemaFile := range []string{"consumer.schema.json", "governance.schema.json", "evidence.schema.json"} {
		t.Run(schemaFile, func(t *testing.T) {
			if got := schemaPathPattern(t, "../../schemas/"+schemaFile); got != SchemaPattern {
				t.Fatalf("path pattern = %q, want %q", got, SchemaPattern)
			}
		})
	}
}

func schemaPathPattern(t *testing.T, filename string) string {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Definitions map[string]struct {
			Pattern string `json:"pattern"`
		} `json:"$defs"`
		Properties map[string]struct {
			Pattern string `json:"pattern"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	if filename == "../../schemas/evidence.schema.json" {
		return schema.Properties["command_id"].Pattern
	}
	return schema.Definitions["path"].Pattern
}
