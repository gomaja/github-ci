package generate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLoadPolicyRejectsIncompleteAndDuplicateLocks(t *testing.T) {
	valid := `schema-version: 1
go-versions:
  current: 1.26.6
  previous: 1.25.13
actions:
  - id: checkout
    repository: actions/checkout
    release: v7.0.1
    sha: 3d3c42e5aac5ba805825da76410c181273ba90b1
tools:
  - id: staticcheck
    version: "2026.1"
    source: https://github.com/dominikh/go-tools
    checksum: h1:w6WUp1VbkqPEgLz4rkBzH/CSU6HkoqNLp6GstyTx3lU=
    parser: staticcheck-jsonl/v1
    profiles: [go-strict, go-library]
    acquisition: go-module
    version-command: staticcheck -version
`
	if _, err := LoadPolicy(strings.NewReader(valid)); err != nil {
		t.Fatalf("LoadPolicy(valid) error = %v", err)
	}

	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "symbolic action", body: strings.Replace(valid, "3d3c42e5aac5ba805825da76410c181273ba90b1", "v7", 1), want: "40-character"},
		{name: "missing checksum", body: strings.Replace(valid, "    checksum: h1:w6WUp1VbkqPEgLz4rkBzH/CSU6HkoqNLp6GstyTx3lU=\n", "", 1), want: "checksum"},
		{name: "missing version command", body: strings.Replace(valid, "    version-command: staticcheck -version\n", "", 1), want: "version-command"},
		{name: "duplicate tool", body: valid + strings.Split(valid, "tools:\n")[1], want: "duplicate tool id"},
		{name: "unknown field", body: valid + "unknown: true\n", want: "field unknown not found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadPolicy(strings.NewReader(test.body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadPolicy() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestLoadLintersRequiresExactly74UniqueEntries(t *testing.T) {
	var body strings.Builder
	body.WriteString("schema-version: 1\nlinters:\n")
	for index := 0; index < 74; index++ {
		fmt.Fprintf(&body, "  - linter%02d\n", index)
	}
	if _, err := LoadLinters(strings.NewReader(body.String())); err != nil {
		t.Fatalf("LoadLinters(valid) error = %v", err)
	}
	if _, err := LoadLinters(strings.NewReader(strings.Replace(body.String(), "  - linter00\n", "  - linter01\n", 1))); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("LoadLinters(duplicate) error = %v", err)
	}
	if _, err := LoadLinters(strings.NewReader(strings.Replace(body.String(), "  - linter00\n", "", 1))); err == nil || !strings.Contains(err.Error(), "exactly 74") {
		t.Fatalf("LoadLinters(short) error = %v", err)
	}
}

func TestCheckedInPolicyBindsSemanticParsers(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "policies", "tools.yaml"))
	if err != nil {
		t.Fatalf("open checked-in policy: %v", err)
	}
	policy, loadErr := LoadPolicy(file)
	closeErr := file.Close()
	if loadErr != nil || closeErr != nil {
		t.Fatalf("load checked-in policy: %v, close: %v", loadErr, closeErr)
	}

	want := map[string]string{
		"go-current":  "command-status/v1",
		"go-previous": "command-status/v1",
		"gopls":       "gopls-diagnostics/v1",
	}
	for _, tool := range policy.Tools {
		parser, exists := want[tool.ID]
		if !exists {
			continue
		}
		if tool.Parser != parser {
			t.Errorf("tool %q parser = %q, want %q", tool.ID, tool.Parser, parser)
		}
		delete(want, tool.ID)
	}
	for tool := range want {
		t.Errorf("checked-in policy is missing tool %q", tool)
	}
}

func TestGenerateIsDeterministicAndVerifyDetectsDrift(t *testing.T) {
	root := fixtureRoot(t)
	if err := Generate(root); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	first := generatedSnapshot(t, root)
	if err := Generate(root); err != nil {
		t.Fatalf("second Generate() error = %v", err)
	}
	second := generatedSnapshot(t, root)
	if !bytes.Equal(first, second) {
		t.Fatal("repeated generation changed output")
	}
	if err := Verify(root); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	workflow := filepath.Join(root, ".github", "workflows", "go.yml")
	if err := os.WriteFile(workflow, append(mustRead(t, workflow), []byte("# drift\n")...), 0o644); err != nil {
		t.Fatalf("introduce drift: %v", err)
	}
	if err := Verify(root); err == nil || !strings.Contains(err.Error(), ".github/workflows/go.yml") {
		t.Fatalf("Verify(drift) error = %v", err)
	}
}

func TestGeneratedArtifactsRejectUnsafeWorkflowConstructs(t *testing.T) {
	root := fixtureRoot(t)
	if err := Generate(root); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	shaUse := regexp.MustCompile(`uses:\s+[^\s]+@([0-9a-f]{40})`)
	for _, name := range generatedPaths {
		data := mustRead(t, filepath.Join(root, filepath.FromSlash(name)))
		text := string(data)
		for _, forbidden := range []string{"continue-on-error:", "pull_request_target:", "container:", "@main", "@master"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden %q", name, forbidden)
			}
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "uses:") && !strings.Contains(line, "./") && !shaUse.MatchString(line) {
				t.Fatalf("%s has mutable action reference %q", name, line)
			}
		}
		if strings.HasPrefix(name, "templates/callers/generated/") && strings.Contains(text, "paths:") {
			t.Fatalf("required caller %s has a workflow path filter", name)
		}
	}
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"policies/tools.yaml", "policies/linters.yaml"} {
		copyFixture(t, filepath.Join("../..", name), filepath.Join(root, name))
	}
	for _, name := range templatePaths {
		copyFixture(t, filepath.Join("../..", name), filepath.Join(root, name))
	}
	return root
}

func copyFixture(t *testing.T, source, destination string) {
	t.Helper()
	data := mustRead(t, source)
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(destination), err)
	}
	if err := os.WriteFile(destination, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", destination, err)
	}
}

func generatedSnapshot(t *testing.T, root string) []byte {
	t.Helper()
	var result []byte
	for _, name := range generatedPaths {
		result = append(result, []byte(name)...)
		result = append(result, 0)
		result = append(result, mustRead(t, filepath.Join(root, filepath.FromSlash(name)))...)
		result = append(result, 0)
	}
	return result
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}
