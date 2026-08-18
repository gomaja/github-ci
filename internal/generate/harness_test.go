package generate

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gomaja/github-ci/internal/evidence"
)

func TestGoCommandHarnessCleanRepository(t *testing.T) {
	if os.Getenv("GITHUB_CI_INTEGRATION") != "1" {
		t.Skip("set GITHUB_CI_INTEGRATION=1 to run pinned analyzer binaries")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	consumer := cleanGoRepository(t)
	artifacts := t.TempDir()
	cli := filepath.Join(artifacts, "github-ci")
	runCommand(t, root, nil, "go", "build", "-o", cli, "./cmd/github-ci")
	plan := filepath.Join(artifacts, "plan.json")
	runCommand(t, root, nil, cli, "preflight", "--repository", consumer, "--config", ".github/github-ci.yaml", "--profile", "go-strict", "--policy", filepath.Join(root, "policies", "tools.yaml"), "--output", plan)

	path := os.Getenv("PATH")
	if home, homeErr := os.UserHomeDir(); homeErr == nil {
		path = filepath.Join(home, "go", "bin") + string(os.PathListSeparator) + path
	}
	for _, group := range []string{"formatting", "core", "tests", "analysis"} {
		output := filepath.Join(artifacts, group)
		environment := []string{
			"GITHUB_CI_CLI=" + cli,
			"SOURCE_DIR=" + consumer,
			"CENTRAL_DIR=" + root,
			"PLAN_PATH=" + plan,
			"CONFIG_PATH=.github/github-ci.yaml",
			"OUTPUT_DIR=" + output,
			"PATH=" + path,
		}
		runCommand(t, root, environment, "bash", filepath.Join(root, "scripts", "run-go-group.sh"), group)
	}

	records, err := filepath.Glob(filepath.Join(artifacts, "*", "records", "*.json"))
	if err != nil {
		t.Fatalf("glob records: %v", err)
	}
	if len(records) != 11 {
		t.Fatalf("record count = %d, want 11: %v", len(records), records)
	}
	for _, name := range records {
		file, openErr := os.Open(name)
		if openErr != nil {
			t.Fatalf("open %s: %v", name, openErr)
		}
		record, readErr := evidence.Read(file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read %s: record error %v, close error %v", name, readErr, closeErr)
		}
		if record.Outcome != evidence.OutcomePass || record.FindingCount != 0 || record.ExitCode != 0 {
			t.Errorf("record %s = %#v, want clean pass", name, record)
		}
	}
}

func TestGoCommandHarnessBlocksFindings(t *testing.T) {
	if os.Getenv("GITHUB_CI_INTEGRATION") != "1" {
		t.Skip("set GITHUB_CI_INTEGRATION=1 to run pinned analyzer binaries")
	}
	tests := []struct {
		name      string
		group     string
		tool      string
		commandID string
		mutate    func(*testing.T, string)
	}{
		{name: "formatting", group: "formatting", tool: "gofmt", commandID: "gofmt/tracked-go", mutate: func(t *testing.T, root string) {
			t.Helper()
			writeFixtureFile(t, root, "clean.go", "// Package clean provides a validation fixture.\npackage clean\nfunc Add(left,right int)int{return left+right}\n")
		}},
		{name: "build", group: "core", tool: "go", commandID: "go/build", mutate: addSyntaxError},
		{name: "gopls", group: "core", tool: "gopls", commandID: "gopls/tracked-go", mutate: addSyntaxError},
		{name: "test", group: "tests", tool: "go", commandID: "go/test", mutate: func(t *testing.T, root string) {
			t.Helper()
			path := filepath.Join(root, "clean_test.go")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read test fixture: %v", err)
			}
			writeFixtureFile(t, root, "clean_test.go", strings.Replace(string(data), "!= 5", "!= 6", 1))
		}},
		{name: "race", group: "tests", tool: "go", commandID: "go/race", mutate: func(t *testing.T, root string) {
			t.Helper()
			writeFixtureFile(t, root, "race_test.go", `package clean

import "testing"

func TestDeliberateRace(t *testing.T) {
	var value int
	done := make(chan struct{})
	go func() {
		value++
		close(done)
	}()
	value++
	<-done
}
`)
		}},
		{name: "vet", group: "core", tool: "go", commandID: "go/vet", mutate: func(t *testing.T, root string) {
			t.Helper()
			writeFixtureFile(t, root, "vet.go", "package clean\n\nimport \"fmt\"\n\nfunc invalidFormat() { fmt.Printf(\"%d\", \"text\") }\n")
		}},
		{name: "staticcheck", group: "analysis", tool: "staticcheck", commandID: "staticcheck/default", mutate: func(t *testing.T, root string) {
			t.Helper()
			writeFixtureFile(t, root, "staticcheck.go", "package clean\n\nimport \"time\"\n\nfunc shortSleep() { time.Sleep(1) }\n")
		}},
		{name: "golangci-lint", group: "analysis", tool: "golangci-lint", commandID: "golangci-lint/default", mutate: func(t *testing.T, root string) {
			t.Helper()
			writeFixtureFile(t, root, "lint.go", "package clean\n\n// TODO: remove the deliberate lint marker.\nfunc lintMarker() {}\n")
		}},
		{name: "govulncheck", group: "analysis", tool: "govulncheck", commandID: "govulncheck/modules", mutate: addSyntaxError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := repositoryRoot(t)
			consumer := cleanGoRepository(t)
			test.mutate(t, consumer)
			runCommand(t, consumer, nil, "git", "add", ".")
			runCommand(t, consumer, nil, "git", "commit", "-m", "test: add deliberate finding")
			artifacts := t.TempDir()
			cli := filepath.Join(artifacts, "github-ci")
			runCommand(t, root, nil, "go", "build", "-o", cli, "./cmd/github-ci")
			plan := filepath.Join(artifacts, "plan.json")
			runCommand(t, root, nil, cli, "preflight", "--repository", consumer, "--config", ".github/github-ci.yaml", "--profile", "go-strict", "--policy", filepath.Join(root, "policies", "tools.yaml"), "--output", plan)
			output := filepath.Join(artifacts, test.group)
			runCommand(t, root, goHarnessEnvironment(t, cli, consumer, root, plan, output), "bash", filepath.Join(root, "scripts", "run-go-group.sh"), test.group)
			name := strings.ReplaceAll(test.tool+"--"+test.commandID, "/", "--") + ".json"
			file, err := os.Open(filepath.Join(output, "records", name))
			if err != nil {
				t.Fatalf("open blocking record: %v", err)
			}
			record, readErr := evidence.Read(file)
			closeErr := file.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("read blocking record: %v, close: %v", readErr, closeErr)
			}
			if record.Outcome != evidence.OutcomeFail || (record.FindingCount == 0 && record.ExitCode == 0) {
				t.Fatalf("record = %#v, want blocking finding or exit", record)
			}
		})
	}
}

func cleanGoRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/github-ci-clean\n\ngo 1.25.0\n",
		"clean.go": `// Package clean provides a validation fixture.
package clean

// Add returns the sum of left and right.
func Add(left, right int) int { return left + right }
`,
		"clean_test.go": `package clean

import "testing"

func TestAdd(t *testing.T) {
	t.Parallel()
	if Add(2, 3) != 5 {
		t.Fatal("unexpected sum")
	}
}
`,
		".github/github-ci.yaml": "schema-version: 1\nprofile: go-strict\n",
	}
	for name, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	commands := [][]string{
		{"init", "-b", "main"},
		{"config", "user.name", "gomaja"},
		{"config", "user.email", "marwanjdid@gmail.com"},
		{"add", "."},
		{"commit", "-m", "test: initialize Go fixture"},
	}
	for _, arguments := range commands {
		runCommand(t, root, nil, "git", arguments...)
	}
	return root
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

func goHarnessEnvironment(t *testing.T, cli, consumer, root, plan, output string) []string {
	t.Helper()
	path := os.Getenv("PATH")
	if home, err := os.UserHomeDir(); err == nil {
		path = filepath.Join(home, "go", "bin") + string(os.PathListSeparator) + path
	}
	return []string{
		"GITHUB_CI_CLI=" + cli,
		"SOURCE_DIR=" + consumer,
		"CENTRAL_DIR=" + root,
		"PLAN_PATH=" + plan,
		"CONFIG_PATH=.github/github-ci.yaml",
		"OUTPUT_DIR=" + output,
		"PATH=" + path,
	}
}

func writeFixtureFile(t *testing.T, root, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(contents), 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
}

func addSyntaxError(t *testing.T, root string) {
	t.Helper()
	writeFixtureFile(t, root, "broken.go", "package clean\n\nfunc broken( {\n")
}

func runCommand(t *testing.T, directory string, environment []string, name string, arguments ...string) {
	t.Helper()
	command := exec.CommandContext(t.Context(), name, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), environment...)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		var detail map[string]any
		_ = json.Unmarshal(output.Bytes(), &detail)
		t.Fatalf("%s %s failed on %s/%s: %v\n%s", name, strings.Join(arguments, " "), runtime.GOOS, runtime.GOARCH, err, output.String())
	}
}
