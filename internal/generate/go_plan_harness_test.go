package generate

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/evidence"
	"github.com/gomaja/github-ci/internal/exceptions"
	"github.com/gomaja/github-ci/internal/gate"
	"github.com/gomaja/github-ci/internal/goexecution"
)

func TestHarnessExecutablePathUsesWindowsSuffix(t *testing.T) {
	base := filepath.Join("temporary", "github-ci")
	if got := harnessExecutablePath(base, "windows"); got != base+".exe" {
		t.Fatalf("Windows executable path = %q, want %q", got, base+".exe")
	}
	if got := harnessExecutablePath(base, "linux"); got != base {
		t.Fatalf("Linux executable path = %q, want %q", got, base)
	}
}

func TestHarnessCLIBuildIsCentralized(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("list package tests: %v", err)
	}
	needle := `"go", "build",` + ` "-o"`
	directBuilds := 0
	for _, name := range files {
		data, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		directBuilds += strings.Count(string(data), needle)
	}
	if directBuilds != 1 {
		t.Fatalf("direct CLI build sites = %d, want one platform-aware helper", directBuilds)
	}
}

func harnessExecutablePath(base, goos string) string {
	if goos == "windows" {
		return base + ".exe"
	}
	return base
}

func buildHarnessCLI(t *testing.T, root, directory string) string {
	t.Helper()
	cli := harnessExecutablePath(filepath.Join(directory, "github-ci"), runtime.GOOS)
	runCommand(t, root, nil, "go", "build", "-o", cli, "./cmd/github-ci")
	return cli
}

func TestSchema2CanaryHarness(t *testing.T) {
	root := repositoryRoot(t)
	temporary := t.TempDir()
	source := filepath.Join(temporary, "source")
	fixture := filepath.Join(root, "testdata", "repositories", "go-canary")
	if err := os.CopyFS(source, os.DirFS(fixture)); err != nil {
		t.Fatalf("copy canary fixture: %v", err)
	}
	for _, arguments := range [][]string{
		{"init", "-b", "main"},
		{"config", "user.name", "gomaja"},
		{"config", "user.email", "marwanjdid@gmail.com"},
		{"add", "."},
		{"commit", "-m", "test: initialize schema 2 canary"},
	} {
		runCommand(t, source, nil, "git", arguments...)
	}
	writeFixtureFile(t, source, "generated/model.go", "package generated\n\nconst Model = \"stale\"\n")
	runCommand(t, filepath.Join(source, "tools"), nil, "bash", filepath.Join(source, "scripts", "check-generated.sh"))
	generated, err := os.ReadFile(filepath.Join(source, "generated", "model.go"))
	if err != nil || !strings.Contains(string(generated), `const Model = "schema-2"`) {
		t.Fatalf("generated source was not restored from a non-root directory: %v\n%s", err, generated)
	}
	assertCanaryRequiresBothTags(t, source)
	runCommand(t, source, nil, "go", "test", "-tags=canary_a,canary_b", "./...")
	runCommand(t, filepath.Join(source, "tools"), nil, "go", "test", "-tags=canary_a,canary_b", "./...")

	cli := buildHarnessCLI(t, root, temporary)
	planPath := filepath.Join(temporary, "plan.json")
	runCommand(t, root, nil, cli, "preflight", "--repository", source, "--config", ".github/github-ci.yaml", "--policy", filepath.Join(root, "policies", "tools.yaml"), "--output", planPath)
	goPlanPath := filepath.Join(temporary, "go-plan.json")
	writeCommandOutput(t, source, goPlanPath, cli, "go-plan", "--repository", source, "--config", ".github/github-ci.yaml")
	goPlan := readGoExecutionPlan(t, goPlanPath)
	assertSchema2CanaryPlan(t, goPlan)

	fakeBin := filepath.Join(temporary, "bin")
	capture := filepath.Join(temporary, "capture")
	writeFakeGoTools(t, fakeBin)
	if err := os.MkdirAll(capture, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"formatting", "core", "tests", "analysis"} {
		output := filepath.Join(temporary, group)
		environment := append(goHarnessEnvironment(t, cli, source, root, planPath, goPlanPath, output), "CAPTURE_DIR="+capture)
		environment = replacePath(environment, fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
		runCommand(t, root, environment, "bash", filepath.Join(root, "scripts", "run-go-group.sh"), group)
	}
	runCommand(t, root, []string{
		"CAPTURE_DIR=" + capture,
		"CENTRAL_DIR=" + root,
		"GO_PLAN_PATH=" + goPlanPath,
		"PATH=" + fakeBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"SOURCE_DIR=" + source,
	}, "bash", filepath.Join(root, "scripts", "run-deep-go.sh"), "portability")

	for _, module := range goPlan.Modules {
		assertCapturedInvocation(t, capture, "go", module.Invocations[goexecution.ToolBuild], nil)
		assertCapturedInvocation(t, capture, "go", module.Invocations[goexecution.ToolTest], func(arguments []string) []string {
			if len(arguments) == 0 || !strings.HasPrefix(arguments[len(arguments)-1], "-coverprofile=") {
				return nil
			}
			return arguments[:len(arguments)-1]
		})
		assertCapturedInvocation(t, capture, "go", module.Invocations[goexecution.ToolRace], nil)
	}
	assertFocusedGoEvidencePasses(t, planPath, temporary)
}

func assertCanaryRequiresBothTags(t *testing.T, source string) {
	t.Helper()
	for _, directory := range []string{source, filepath.Join(source, "tools")} {
		for _, tags := range []string{"", "canary_a", "canary_b"} {
			arguments := []string{"test"}
			if tags != "" {
				arguments = append(arguments, "-tags="+tags)
			}
			arguments = append(arguments, "./...")
			command := exec.CommandContext(t.Context(), "go", arguments...)
			command.Dir = directory
			if err := command.Run(); err == nil {
				t.Fatalf("canary unexpectedly compiled in %s with tags %q", directory, tags)
			}
		}
	}
}

func assertSchema2CanaryPlan(t *testing.T, plan goexecution.Plan) {
	t.Helper()
	if len(plan.Modules) != 2 || plan.Modules[0].Path != "." || plan.Modules[1].Path != "tools" {
		t.Fatalf("canary modules = %#v, want root and tools", plan.Modules)
	}
	root := plan.Modules[0]
	if !reflect.DeepEqual(root.Packages, []string{".", "./generated"}) || root.ModuleMode != config.ModuleModeReadonly ||
		!reflect.DeepEqual(root.BuildTags, []string{"canary_a", "canary_b"}) || root.TestTimeout != "12m" ||
		root.PackageParallelism != 3 || root.RaceParallelism != 1 || !reflect.DeepEqual(root.CoveragePackages, []string{"."}) {
		t.Fatalf("root canary plan = %#v", root)
	}
	tools := plan.Modules[1]
	if !reflect.DeepEqual(tools.Packages, []string{"."}) || tools.ModuleMode != config.ModuleModeMod ||
		!reflect.DeepEqual(tools.BuildTags, []string{"canary_a", "canary_b"}) || tools.TestTimeout != "7m" ||
		tools.PackageParallelism != 2 || tools.RaceParallelism != 1 || tools.CoveragePackages == nil || len(tools.CoveragePackages) != 0 {
		t.Fatalf("tools canary plan = %#v", tools)
	}
}

func assertFocusedGoEvidencePasses(t *testing.T, planPath, artifacts string) {
	t.Helper()
	data, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	var plan evidence.Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	recordPaths, err := filepath.Glob(filepath.Join(artifacts, "*", "records", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	expectedByID := make(map[string]evidence.Expected, len(plan.Expected))
	for _, expected := range plan.Expected {
		expectedByID[expected.Identity()] = expected
	}
	records := make([]evidence.Record, 0, len(recordPaths))
	for _, name := range recordPaths {
		file, openErr := os.Open(name)
		if openErr != nil {
			t.Fatal(openErr)
		}
		record, readErr := evidence.Read(file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read %s: %v; close: %v", name, readErr, closeErr)
		}
		if _, exists := expectedByID[record.Identity()]; !exists {
			t.Fatalf("record %q is not expected", record.Identity())
		}
		records = append(records, record)
	}
	if len(records) != 11 {
		t.Fatalf("Go evidence record count = %d, want 11", len(records))
	}
	selected := make(map[string]struct{}, len(records))
	for _, record := range records {
		selected[record.Identity()] = struct{}{}
	}
	focused := plan
	focused.Expected = nil
	for _, expected := range plan.Expected {
		if _, exists := selected[expected.Identity()]; exists {
			focused.Expected = append(focused.Expected, expected)
		}
	}
	digest, err := focused.Digest()
	if err != nil {
		t.Fatal(err)
	}
	contexts := make([]gate.RecordContext, 0, len(records))
	for _, record := range records {
		expected := expectedByID[record.Identity()]
		context := gate.RecordContext{
			Tool: record.Tool, CommandID: record.CommandID, SubjectSHA: record.SubjectSHA,
			PlanSHA256: digest, TreeSHA256: focused.TreeSHA256, DetectorVersion: focused.DetectorVersion,
			PolicySHA256: focused.PolicySHA256, Execution: gate.ExecutionCompleted,
		}
		if record.Applicability == evidence.Applicable {
			context.Report = &gate.ReportEvidence{SHA256: record.ReportSHA256, ParserVersion: expected.ParserVersion}
		}
		contexts = append(contexts, context)
	}
	result := gate.Evaluate(gate.Input{
		Plan: focused, Records: records, Context: contexts, Exceptions: exceptions.Set{},
		ObservedSubjectSHA: focused.SubjectSHA, ObservedTreeSHA256: focused.TreeSHA256,
		ObservedPolicySHA256: focused.PolicySHA256, ObservedPlanSHA256: digest, EvaluationDate: "2026-08-19",
	})
	if !result.Pass {
		t.Fatalf("focused Go evidence gate = %#v", result)
	}
}

func replacePath(environment []string, value string) []string {
	result := append([]string{}, environment...)
	for index := range result {
		if strings.HasPrefix(result[index], "PATH=") {
			result[index] = "PATH=" + value
			return result
		}
	}
	return append(result, "PATH="+value)
}

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
	cli := buildHarnessCLI(t, root, t.TempDir())
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

func TestRunDeepGoExecutesPlannedPortabilityAndTaggedFuzz(t *testing.T) {
	root := repositoryRoot(t)
	temporary := t.TempDir()
	source := filepath.Join(temporary, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	goPlan := writeGoExecutionPlan(t, temporary)
	fakeBin := filepath.Join(temporary, "bin")
	capture := filepath.Join(temporary, "capture")
	writeFakeGoTools(t, fakeBin)
	if err := os.MkdirAll(capture, 0o755); err != nil {
		t.Fatal(err)
	}
	environment := []string{
		"CAPTURE_DIR=" + capture,
		"CENTRAL_DIR=" + root,
		"FUZZ_TIME=1s",
		"GO_PLAN_PATH=" + goPlan,
		"PATH=" + fakeBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"SOURCE_DIR=" + source,
	}
	runCommand(t, root, environment, "bash", filepath.Join(root, "scripts", "run-deep-go.sh"), "portability")
	runCommand(t, root, environment, "bash", filepath.Join(root, "scripts", "run-deep-go.sh"), "fuzz-benchmark")

	module := readGoExecutionPlan(t, goPlan).Modules[0]
	assertCapturedInvocation(t, capture, "go", module.Invocations[goexecution.ToolBuild], nil)
	assertCapturedInvocation(t, capture, "go", module.Invocations[goexecution.ToolVet], nil)
	assertCapturedInvocation(t, capture, "go", module.Invocations[goexecution.ToolTest], nil)
	assertCapturedGoArguments(t, capture, []string{"list", "-mod=vendor", "-tags=sqlite,integration", "./cmd/...", "./internal/..."})
	assertCapturedGoArguments(t, capture, []string{"-mod=vendor", "-tags=sqlite,integration", "example.com/fixture", "-fuzz=^FuzzBare$", "-fuzztime=1s"})
	assertCapturedGoArguments(t, capture, []string{"-mod=vendor", "-tags=sqlite,integration", "./cmd/...", "./internal/...", "-bench=.", "-benchtime=1s"})
}

func TestRunDeepGoFailsClosedWhenDiscoveryReturnsPartialOutput(t *testing.T) {
	root := repositoryRoot(t)
	for _, variable := range []string{"FAIL_GO_LIST", "FAIL_FUZZ_LIST"} {
		t.Run(variable, func(t *testing.T) {
			temporary := t.TempDir()
			fakeBin := filepath.Join(temporary, "bin")
			capture := filepath.Join(temporary, "capture")
			writeFakeGoTools(t, fakeBin)
			if err := os.MkdirAll(capture, 0o755); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "scripts", "run-deep-go.sh"), "fuzz-benchmark")
			command.Dir = root
			command.Env = append(os.Environ(),
				"CAPTURE_DIR="+capture,
				"CENTRAL_DIR="+root,
				"FUZZ_TIME=1s",
				"GO_PLAN_PATH="+writeGoExecutionPlan(t, temporary),
				"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"SOURCE_DIR="+temporary,
				variable+"=true",
			)
			if err := command.Run(); err == nil {
				t.Fatalf("run-deep-go ignored a partial-output failure from %s", variable)
			}
		})
	}
}

func TestRunDeepGoRejectsInvalidFuzzDurationBeforeExecution(t *testing.T) {
	root := repositoryRoot(t)
	temporary := t.TempDir()
	environment := append(os.Environ(),
		"CENTRAL_DIR="+root,
		"FUZZ_TIME=0s",
		"GO_PLAN_PATH="+writeGoExecutionPlan(t, temporary),
		"SOURCE_DIR="+temporary,
	)
	command := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "scripts", "run-deep-go.sh"), "fuzz-benchmark")
	command.Dir = root
	command.Env = environment
	if err := command.Run(); err == nil {
		t.Fatal("run-deep-go accepted a zero fuzz duration")
	}
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
    if [[ "${1:-}" == list ]]; then
      printf 'example.com/fixture\n'
      [[ "${FAIL_GO_LIST:-false}" != true ]] || exit 42
    fi
    for argument in "$@"; do
      if [[ "$argument" == -list=* ]]; then
        printf 'FuzzBare\n'
        [[ "${FAIL_FUZZ_LIST:-false}" != true ]] || exit 43
      fi
    done
    ;;
  staticcheck)
    if [[ "${1:-}" == -version ]]; then printf 'staticcheck fixture\n'; fi
    ;;
  golangci-lint)
    output=''
    while (($#)); do
      if [[ "$1" == --output.json.path ]]; then output=$2; shift 2; else shift; fi
    done
    if [[ -n "$output" ]]; then mkdir -p "$(dirname "$output")"; printf '{"Issues":[],"Report":{"Linters":[]}}\n' >"$output"; fi
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
	for _, tool := range []string{"go", "gofmt", "goimports", "gopls", "staticcheck", "golangci-lint", "govulncheck", "gotestsum"} {
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

func assertCapturedGoArguments(t *testing.T, directory string, required []string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(directory, "go.*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		data, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		fields := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
		if len(fields) < 3 {
			continue
		}
		arguments := fields[2:]
		matched := true
		for _, value := range required {
			if !slices.Contains(arguments, value) {
				matched = false
				break
			}
		}
		if matched {
			return
		}
	}
	t.Fatalf("no captured go invocation contains %#v", required)
}
