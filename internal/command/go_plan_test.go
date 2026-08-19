package command

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/github-ci/internal/goexecution"
)

func TestRunGoPlanEmitsCanonicalTypedPlan(t *testing.T) {
	repository := goPlanRepository(t)
	args := []string{"go-plan", "--repository", repository, "--config", ".github/github-ci.yaml"}
	code, first, stderr := runForTest(t, args)
	if code != exitSuccess {
		t.Fatalf("go-plan code = %d, stderr = %q", code, stderr)
	}
	code, second, stderr := runForTest(t, args)
	if code != exitSuccess || second != first {
		t.Fatalf("second go-plan code = %d, deterministic = %t, stderr = %q", code, second == first, stderr)
	}

	var plan goexecution.Plan
	if err := json.Unmarshal([]byte(first), &plan); err != nil {
		t.Fatalf("unmarshal go-plan output: %v", err)
	}
	if plan.SchemaVersion != goexecution.SchemaVersion || len(plan.Modules) != 2 {
		t.Fatalf("plan identity = (%q, %d modules)", plan.SchemaVersion, len(plan.Modules))
	}
	if plan.Modules[0].Path != "." || plan.Modules[1].Path != "tools" {
		t.Fatalf("module order = %q, %q", plan.Modules[0].Path, plan.Modules[1].Path)
	}
	want := []string{"go", "build", "-mod=readonly", "-p=2", "-tags=sqlite,integration", "./..."}
	if got := plan.Modules[0].Invocations[goexecution.ToolBuild].Arguments; !reflect.DeepEqual(got, want) {
		t.Fatalf("root build arguments = %#v, want %#v", got, want)
	}
	if coverage := plan.Modules[1].CoveragePackages; coverage == nil || len(coverage) != 0 {
		t.Fatalf("tools coverage = %#v, want explicit empty", coverage)
	}
}

func TestRunGoPlanRejectsIncompleteOrPositionalInput(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"go-plan"}, want: "--config is required"},
		{args: []string{"go-plan", "--config", ".github/github-ci.yaml", "extra"}, want: "unexpected positional argument"},
	}
	for _, test := range tests {
		code, _, stderr := runForTest(t, test.args)
		if code != exitError || !strings.Contains(stderr, test.want) {
			t.Fatalf("Run(%v) code = %d, stderr = %q, want %q", test.args, code, stderr, test.want)
		}
	}
}

func goPlanRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod":        "module example.com/root\n\ngo 1.25.0\n",
		"root.go":       "package root\n",
		"tools/go.mod":  "module example.com/tools\n\ngo 1.25.0\n",
		"tools/tool.go": "package tools\n",
		".github/github-ci.yaml": `schema-version: 2
profile: go-library
go:
  defaults:
    packages: [./...]
    module-mode: readonly
    build-tags: [sqlite, integration]
    test-timeout: 10m
    package-parallelism: 2
    race-parallelism: 1
    coverage-packages: [./...]
  modules:
    - path: .
    - path: tools
      coverage-packages: []
`,
	}
	for name, contents := range files {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		mustWrite(t, filename, contents)
	}
	for _, args := range [][]string{
		{"init", "-b", "main"},
		{"config", "user.name", "gomaja"},
		{"config", "user.email", "marwanjdid@gmail.com"},
		{"add", "."},
		{"commit", "-m", "test: initialize Go plan fixture"},
	} {
		command := exec.CommandContext(t.Context(), "git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
		}
	}
	return root
}
