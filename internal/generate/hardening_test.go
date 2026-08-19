package generate

import (
	"strings"
	"testing"
)

func TestValidateToolRejectsSourceURLComponentsIndependently(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{name: "wrong scheme", source: "http://example.com/tool"},
		{name: "missing host", source: "https:tool"},
		{name: "user info", source: "https://user@example.com/tool"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tool := validHardeningTool()
			tool.Source = test.source
			if err := validateTool(tool); err == nil || err.Error() != `tool "tool" source must be an absolute HTTPS URL` {
				t.Fatalf("validateTool() error = %v", err)
			}
		})
	}
}

func TestValidateVersionRejectsEmptyAndControlValuesIndependently(t *testing.T) {
	for _, value := range []string{" ", "1.2.3\n"} {
		if err := validateVersion("version", value); err == nil || err.Error() != "version must not be empty or contain controls" {
			t.Fatalf("validateVersion(%q) error = %v", value, err)
		}
	}
	if err := validateVersion("version", "1.2.3"); err != nil {
		t.Fatalf("validateVersion(valid) error = %v", err)
	}
}

func TestValidRepositoryRejectsStructureAndOwnerIndependently(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "actions", want: false},
		{value: "InvalidOwner/checkout", want: false},
		{value: "actions/checkout", want: true},
	}
	for _, test := range tests {
		if got := validRepository(test.value); got != test.want {
			t.Errorf("validRepository(%q) = %t, want %t", test.value, got, test.want)
		}
	}
}

func validHardeningTool() Tool {
	return Tool{
		ID:             "tool",
		Version:        "1.0.0",
		Source:         "https://example.com/tool",
		Checksum:       "sha256:" + strings.Repeat("a", 64),
		Parser:         "json/v1",
		Profiles:       []string{"go-strict"},
		Acquisition:    "go-module",
		VersionCommand: "tool --version",
	}
}
