package generate

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var unsafeShellCommands = []*regexp.Regexp{
	regexp.MustCompile(`(?m)(^|[[:space:];|&()])eval(?:[[:space:]'"$\\]|$)`),
	regexp.MustCompile(`(?m)(^|[[:space:];|&()])bash[[:space:]]+-c(?:[[:space:]]|$)`),
}

func TestGoPlanShellUsesQuotedArraysWithoutEvaluation(t *testing.T) {
	for _, name := range []string{"../../scripts/load-go-plan.sh", "../../scripts/run-go-group.sh"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(data)
		for _, pattern := range unsafeShellCommands {
			if pattern.MatchString(text) {
				t.Errorf("%s contains unsafe execution matching %q", name, pattern)
			}
		}
		for _, variable := range []string{"GO_PLAN_ENVIRONMENT", "GO_PLAN_ARGUMENTS"} {
			expansion := "${" + variable + "[@]}"
			withoutQuoted := strings.ReplaceAll(text, `"`+expansion+`"`, "")
			if strings.Contains(withoutQuoted, expansion) {
				t.Errorf("%s contains an unquoted %s array expansion", name, variable)
			}
		}
	}
	runner, err := os.ReadFile("../../scripts/run-go-group.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"${GO_PLAN_ARGUMENTS[@]}"`, `env "${GO_PLAN_ENVIRONMENT[@]}"`} {
		if !strings.Contains(string(runner), required) {
			t.Errorf("run-go-group.sh is missing quoted array form %q", required)
		}
	}
}

func TestUnsafeShellCommandPatternsCoverEquivalentSpellings(t *testing.T) {
	for _, text := range []string{
		"eval command",
		"eval$'\\t'command",
		`eval" command"`,
		"bash -c command",
		"bash\t-c command",
	} {
		matched := false
		for _, pattern := range unsafeShellCommands {
			matched = matched || pattern.MatchString(text)
		}
		if !matched {
			t.Errorf("unsafe shell form was not detected: %q", text)
		}
	}
	for _, text := range []string{"evaluate command", "bash command"} {
		for _, pattern := range unsafeShellCommands {
			if pattern.MatchString(text) {
				t.Errorf("safe shell form %q matched %q", text, pattern)
			}
		}
	}
}

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
