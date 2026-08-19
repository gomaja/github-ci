package generate

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/goexecution"
)

func TestGoPlanRejectsArgumentInjectionBeforeExecution(t *testing.T) {
	root := repositoryRoot(t)
	repository := t.TempDir()
	writeFixtureFile(t, repository, "go.mod", "module example.com/injection\n\ngo 1.25.0\n")
	writeFixtureFile(t, repository, "main.go", "package injection\n")
	if err := os.MkdirAll(filepath.Join(repository, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, repository, ".github/github-ci.yaml", `schema-version: 2
profile: go-strict
go:
  defaults:
    packages: ['$(touch escaped)']
`)
	for _, arguments := range [][]string{
		{"init", "-b", "main"},
		{"config", "user.name", "gomaja"},
		{"config", "user.email", "marwanjdid@gmail.com"},
		{"add", "."},
		{"commit", "-m", "test: initialize injection fixture"},
	} {
		runCommand(t, repository, nil, "git", arguments...)
	}
	cli := filepath.Join(t.TempDir(), "github-ci")
	runCommand(t, root, nil, "go", "build", "-o", cli, "./cmd/github-ci")
	command := exec.CommandContext(t.Context(), cli, "go-plan", "--repository", repository, "--config", ".github/github-ci.yaml")
	command.Dir = repository
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err == nil || !strings.Contains(output.String(), "invalid package pattern") {
		t.Fatalf("go-plan error = %v, output = %q", err, output.String())
	}
	if _, err := os.Stat(filepath.Join(repository, "escaped")); !os.IsNotExist(err) {
		t.Fatalf("injection marker stat error = %v, want not-exist", err)
	}
}

func TestRunGoGroupExecutesTypedArgumentArrays(t *testing.T) {
	root := repositoryRoot(t)
	temporary := t.TempDir()
	source := filepath.Join(temporary, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, source, "main.go", "package fixture\n")
	goPlan := writeGoExecutionPlan(t, temporary)
	fakeCLI := writeFakeGoGroupCLI(t, temporary)
	fakeBin := filepath.Join(temporary, "bin")
	capture := filepath.Join(temporary, "capture")
	writeFakeGoTools(t, fakeBin)
	if err := os.MkdirAll(capture, 0o755); err != nil {
		t.Fatal(err)
	}

	environment := []string{
		"CAPTURE_DIR=" + capture,
		"CENTRAL_DIR=" + root,
		"CONFIG_PATH=.github/github-ci.yaml",
		"GITHUB_CI_CLI=" + fakeCLI,
		"GO_PLAN_PATH=" + goPlan,
		"OUTPUT_DIR=" + filepath.Join(temporary, "output"),
		"PATH=" + fakeBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"PLAN_PATH=" + filepath.Join(temporary, "applicability-plan.json"),
		"SOURCE_DIR=" + source,
	}
	for _, group := range []string{"core", "tests", "analysis"} {
		runCommand(t, root, environment, "bash", filepath.Join(root, "scripts", "run-go-group.sh"), group)
	}

	plan := readGoExecutionPlan(t, goPlan)
	module := plan.Modules[0]
	assertCapturedInvocation(t, capture, "go", module.Invocations[goexecution.ToolBuild], nil)
	assertCapturedInvocation(t, capture, "go", module.Invocations[goexecution.ToolVet], nil)
	assertCapturedInvocation(t, capture, "go", module.Invocations[goexecution.ToolRace], nil)
	assertCapturedInvocation(t, capture, "go", module.Invocations[goexecution.ToolTest], func(arguments []string) []string {
		if len(arguments) == 0 || !strings.HasPrefix(arguments[len(arguments)-1], "-coverprofile=") {
			return nil
		}
		return arguments[:len(arguments)-1]
	})
	assertCapturedInvocation(t, capture, "gopls", module.Invocations[goexecution.ToolGopls], func(arguments []string) []string {
		if len(arguments) == 0 || arguments[len(arguments)-1] != "main.go" {
			return nil
		}
		return arguments[:len(arguments)-1]
	})
	assertCapturedInvocation(t, capture, "staticcheck", module.Invocations[goexecution.ToolStaticcheck], nil)
	assertCapturedInvocation(t, capture, "golangci-lint", module.Invocations[goexecution.ToolGolangCILint], func(arguments []string) []string {
		return removeTrustedGolangCIArguments(t, arguments)
	})
	assertCapturedInvocation(t, capture, "govulncheck", module.Invocations[goexecution.ToolGovulncheck], nil)
}

func writeGoExecutionPlan(t *testing.T, root string) string {
	t.Helper()
	packages := []string{"./cmd/...", "./internal/..."}
	mode := config.ModuleModeVendor
	tags := []string{"sqlite", "integration"}
	timeout := "12m"
	parallel := 3
	race := 2
	coverage := []string{"./cmd/..."}
	consumer := config.Consumer{
		SchemaVersion: 2,
		Profile:       config.ProfileGoStrict,
		Go: &config.Go{Defaults: config.GoSettings{
			Packages: &packages, ModuleMode: &mode, BuildTags: &tags, TestTimeout: &timeout,
			PackageParallelism: &parallel, RaceParallelism: &race, CoveragePackages: &coverage,
		}},
	}
	plan, err := goexecution.Resolve(consumer, []string{"."})
	if err != nil {
		t.Fatalf("resolve fixture Go plan: %v", err)
	}
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal fixture Go plan: %v", err)
	}
	name := filepath.Join(root, "go-plan.json")
	writeFixtureFile(t, root, "go-plan.json", string(data)+"\n")
	return name
}

func readGoExecutionPlan(t *testing.T, name string) goexecution.Plan {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var plan goexecution.Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func writeFakeGoGroupCLI(t *testing.T, root string) string {
	t.Helper()
	script := `#!/usr/bin/env bash
set -euo pipefail
command_name=${1:?}
shift
case "$command_name" in
  modules)
    printf '{"profile":"go-strict","modules":["."]}\n'
    ;;
  files)
    printf 'main.go\0'
    ;;
  applicable)
    ;;
  aggregate|record)
    output=''
    while (($#)); do
      if [[ "$1" == --output ]]; then output=$2; shift 2; else shift; fi
    done
    [[ -n "$output" ]]
    mkdir -p "$(dirname "$output")"
    printf '{}\n' >"$output"
    ;;
  *)
    exit 91
    ;;
esac
`
	name := filepath.Join(root, "fake-cli")
	writeFixtureFile(t, root, "fake-cli", script)
	if err := os.Chmod(name, 0o755); err != nil {
		t.Fatal(err)
	}
	return name
}

func writeFakeGoTools(t *testing.T, directory string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/usr/bin/env bash
set -euo pipefail
tool=$(basename "$0")
record=$(mktemp "$CAPTURE_DIR/$tool.XXXXXX")
printf '%s\0' "${GOFLAGS:-}" "${GOMAXPROCS:-}" "$@" >"$record"
case "$tool" in
  go)
    if [[ "${1:-}" == version ]]; then printf 'go version go1.26.6 fixture/amd64\n'; fi
    ;;
  golangci-lint)
    output=''
    while (($#)); do
      if [[ "$1" == --output.json.path ]]; then output=$2; shift 2; else shift; fi
    done
    if [[ -n "$output" ]]; then mkdir -p "$(dirname "$output")"; printf '{"Issues":[],"Report":{}}\n' >"$output"; fi
    ;;
  govulncheck)
    printf '{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}\n'
    ;;
  gotestsum)
    if [[ "${1:-}" == --version ]]; then printf 'gotestsum version fixture\n'; exit 0; fi
    junit=''
    test_arguments=()
    after_separator=false
    while (($#)); do
      if [[ "$after_separator" == true ]]; then
        test_arguments+=("$1")
      elif [[ "$1" == --junitfile ]]; then
        junit=$2
        shift
      elif [[ "$1" == -- ]]; then
        after_separator=true
      fi
      shift
    done
    set +e
    go test "${test_arguments[@]}"
    status=$?
    set -e
    failures=0
    ((status == 0)) || failures=1
    printf '<testsuites tests="1" failures="%s" errors="0"></testsuites>\n' "$failures" >"$junit"
    exit "$status"
    ;;
esac
`
	for _, tool := range []string{"go", "gopls", "staticcheck", "golangci-lint", "govulncheck", "gotestsum"} {
		name := filepath.Join(directory, tool)
		if err := os.WriteFile(name, []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", tool, err)
		}
	}
}

func assertCapturedInvocation(t *testing.T, directory, tool string, want goexecution.Invocation, normalize func([]string) []string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(directory, tool+".*"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	for _, name := range files {
		data, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		fields := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
		if len(fields) < 3 {
			continue
		}
		environment := []string{}
		if fields[0] != "" {
			environment = append(environment, "GOFLAGS="+fields[0])
		}
		if fields[1] != "" {
			environment = append(environment, "GOMAXPROCS="+fields[1])
		}
		arguments := append([]string{tool}, fields[2:]...)
		if normalize != nil {
			arguments = normalize(arguments)
			if arguments == nil {
				continue
			}
		}
		if reflect.DeepEqual(environment, want.Environment) && reflect.DeepEqual(arguments, want.Arguments) {
			return
		}
	}
	t.Fatalf("no captured %s invocation matched environment %#v and arguments %#v", tool, want.Environment, want.Arguments)
}

func removeTrustedGolangCIArguments(t *testing.T, arguments []string) []string {
	t.Helper()
	trusted := map[string]bool{"--config": true, "--output.text.path": true, "--output.json.path": true}
	result := make([]string, 0, len(arguments))
	for index := 0; index < len(arguments); index++ {
		if trusted[arguments[index]] {
			if index+1 >= len(arguments) {
				t.Fatalf("missing value after %s", arguments[index])
			}
			index++
			continue
		}
		result = append(result, arguments[index])
	}
	return result
}
