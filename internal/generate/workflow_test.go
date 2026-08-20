package generate

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGoWorkflowContract(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/go.yml")
	if err != nil {
		t.Fatalf("read Go workflow: %v", err)
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("decode Go workflow: %v", err)
	}
	assertWorkflowCallContract(t, workflow)
	assertWorkflowPermissions(t, workflow)
	jobs := assertWorkflowJobs(t, workflow)
	assertWorkflowJobContracts(t, jobs)
	assertWorkflowExecutionContracts(t, jobs)
	assertGoPlanWorkflowContract(t, jobs, string(data))
	assertBootstrapNetworkAccess(t, jobs)
	assertScannerRuntimeContracts(t, jobs)
	assertWorkflowTextContracts(t, string(data))
}

func TestCodeQLAnalysisCategoryIsStableAcrossCallers(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/go.yml")
	if err != nil {
		t.Fatalf("read Go workflow: %v", err)
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("decode Go workflow: %v", err)
	}
	jobs := mapping(t, workflow["jobs"], "jobs")
	codeql := mapping(t, jobs["codeql"], "codeql")
	for _, rawStep := range sequence(t, codeql["steps"], "codeql steps") {
		step := mapping(t, rawStep, "codeql step")
		if step["name"] != "Analyze CodeQL database" {
			continue
		}
		with := mapping(t, step["with"], "CodeQL analyze inputs")
		if with["category"] != "github-ci/${{ matrix.language }}" {
			t.Fatalf("CodeQL category = %#v, want stable language category", with["category"])
		}
		return
	}
	t.Fatal("CodeQL analyze step is missing")
}

func TestGeneratedWorkflowsUseFoldedEgressAllowLists(t *testing.T) {
	for _, name := range []string{
		"../../.github/workflows/go.yml",
		"../../.github/workflows/deep.yml",
		"../../.github/workflows/release.yml",
	} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(data)
		if strings.Contains(text, "allowed-endpoints: |\n") {
			t.Errorf("%s uses a newline-delimited Harden Runner allowlist", name)
		}
		if !strings.Contains(text, "allowed-endpoints: >-\n") {
			t.Errorf("%s has no space-folded Harden Runner allowlist", name)
		}
	}
}

func TestGeneratedWorkflowsBindHelpersToDefiningWorkflow(t *testing.T) {
	for _, name := range []string{
		"../../.github/workflows/go.yml",
		"../../.github/workflows/deep.yml",
		"../../.github/workflows/release.yml",
	} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(data)
		if strings.Contains(text, "github.workflow_sha") {
			t.Errorf("%s binds helpers to the caller workflow SHA", name)
		}
		var workflow map[string]any
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		jobs := mapping(t, workflow["jobs"], name+" jobs")
		helperCheckouts := 0
		for jobName, rawJob := range jobs {
			job := mapping(t, rawJob, name+" job "+jobName)
			steps, _ := job["steps"].([]any)
			for _, rawStep := range steps {
				step := mapping(t, rawStep, name+" job "+jobName+" step")
				uses, _ := step["uses"].(string)
				if !strings.HasPrefix(uses, "actions/checkout@") {
					continue
				}
				with := mapping(t, step["with"], name+" job "+jobName+" checkout.with")
				if with["path"] != "github-ci" {
					continue
				}
				helperCheckouts++
				if with["repository"] != "${{ job.workflow_repository }}" || with["ref"] != "${{ job.workflow_sha }}" {
					t.Errorf("%s job %s helper checkout is not bound to the defining workflow", name, jobName)
				}
			}
		}
		if helperCheckouts == 0 {
			t.Errorf("%s has no helper checkout at path github-ci", name)
		}
	}
}

func TestBootstrapBuildsFromItsActionBoundRepository(t *testing.T) {
	data, err := os.ReadFile("../../actions/bootstrap/action.yml")
	if err != nil {
		t.Fatalf("read bootstrap action: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, `CENTRAL_DIR: ${{ github.action_path }}/../..`) {
		t.Error("bootstrap action does not derive its repository from github.action_path")
	}
	if strings.Contains(text, `CENTRAL_DIR: ${{ github.workspace }}/github-ci`) {
		t.Error("bootstrap action assumes a workspace checkout named github-ci")
	}
}

func TestBootstrapInstallsGo127CompatibleAnalyzers(t *testing.T) {
	data, err := os.ReadFile("../../actions/bootstrap/action.yml")
	if err != nil {
		t.Fatalf("read bootstrap action: %v", err)
	}
	text := string(data)
	for _, required := range []string{
		"github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.0",
		`grep -F '2.13.0'`,
		"honnef.co/go/tools/cmd/staticcheck@v0.8.0-rc.1",
		`grep -F '2026.2rc1 (0.8.0-rc.1)'`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("bootstrap action is missing %q", required)
		}
	}
	for _, obsolete := range []string{"golangci-lint@v2.12.2", "staticcheck@v0.7.0"} {
		if strings.Contains(text, obsolete) {
			t.Errorf("bootstrap action retains obsolete analyzer lock %q", obsolete)
		}
	}
}

func TestStandardAndDeepWorkflowsUploadDistinctArtifacts(t *testing.T) {
	standard := uploadedArtifactNames(t, "../../.github/workflows/go.yml")
	deep := uploadedArtifactNames(t, "../../.github/workflows/deep.yml")
	for name := range standard {
		if _, exists := deep[name]; exists {
			t.Errorf("standard and deep workflows both upload artifact %q", name)
		}
	}
}

func uploadedArtifactNames(t *testing.T, name string) map[string]struct{} {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	names := map[string]struct{}{}
	for jobName, rawJob := range mapping(t, workflow["jobs"], name+" jobs") {
		job := mapping(t, rawJob, name+" job "+jobName)
		steps, _ := job["steps"].([]any)
		for _, rawStep := range steps {
			step := mapping(t, rawStep, name+" job "+jobName+" step")
			uses, _ := step["uses"].(string)
			if !strings.HasPrefix(uses, "actions/upload-artifact@") {
				continue
			}
			with := mapping(t, step["with"], name+" job "+jobName+" upload.with")
			artifact, ok := with["name"].(string)
			if !ok || artifact == "" {
				t.Fatalf("%s job %s upload has no literal artifact name", name, jobName)
			}
			if _, exists := names[artifact]; exists {
				t.Fatalf("%s uploads duplicate artifact %q", name, artifact)
			}
			names[artifact] = struct{}{}
		}
	}
	return names
}

func assertWorkflowCallContract(t *testing.T, workflow map[string]any) {
	t.Helper()
	on := mapping(t, workflow["on"], "on")
	workflowCall := mapping(t, on["workflow_call"], "on.workflow_call")
	inputs := mapping(t, workflowCall["inputs"], "on.workflow_call.inputs")
	if len(inputs) != 1 {
		t.Errorf("workflow_call inputs = %#v, want config-path only", inputs)
	}
	if _, exists := inputs["config-path"]; !exists {
		t.Error("workflow_call input config-path is missing")
	}
}

func assertWorkflowPermissions(t *testing.T, workflow map[string]any) {
	t.Helper()
	permissions := mapping(t, workflow["permissions"], "permissions")
	if len(permissions) != 1 || permissions["contents"] != "read" {
		t.Errorf("workflow permissions = %#v, want contents: read only", permissions)
	}
}

func assertWorkflowJobs(t *testing.T, workflow map[string]any) map[string]any {
	t.Helper()
	jobs := mapping(t, workflow["jobs"], "jobs")
	for _, name := range []string{"preflight", "formatting", "core", "tests", "analysis", "compatibility", "codeql", "dependency-review", "security", "supply-chain", "repository", "scorecard", "evidence", "gate"} {
		if _, exists := jobs[name]; !exists {
			t.Errorf("required job %q is missing", name)
		}
	}
	return jobs
}

func assertWorkflowJobContracts(t *testing.T, jobs map[string]any) {
	t.Helper()
	for name, raw := range jobs {
		job := mapping(t, raw, "job "+name)
		if timeout, ok := job["timeout-minutes"].(int); !ok || timeout <= 0 || timeout > 60 {
			t.Errorf("job %q timeout-minutes = %#v, want 1..60", name, job["timeout-minutes"])
		}
		assertNoExpressionsInRun(t, name, job)
	}
}

func assertDeepWorkflowTimeouts(t *testing.T, jobs map[string]any) {
	t.Helper()
	for name, raw := range jobs {
		job := mapping(t, raw, "deep "+name)
		timeout, ok := job["timeout-minutes"].(int)
		if !ok || timeout <= 0 {
			t.Errorf("deep job %q timeout-minutes = %#v, want a positive integer", name, job["timeout-minutes"])
			continue
		}
		if name == "mutation" {
			if timeout != 90 {
				t.Errorf("deep mutation timeout-minutes = %d, want 90", timeout)
			}
			continue
		}
		if timeout > 60 {
			t.Errorf("deep job %q timeout-minutes = %d, want at most 60", name, timeout)
		}
	}
}

func assertWorkflowExecutionContracts(t *testing.T, jobs map[string]any) {
	t.Helper()
	preflight := mapping(t, jobs["preflight"], "preflight")
	assertDualCheckout(t, preflight)
	outputs := mapping(t, preflight["outputs"], "preflight.outputs")
	if outputs["profile"] != "${{ steps.consumer.outputs.profile }}" || outputs["has-go"] != "${{ steps.consumer.outputs.has-go }}" {
		t.Errorf("preflight outputs = %#v", outputs)
	}
	compatibility := mapping(t, jobs["compatibility"], "compatibility")
	strategy := mapping(t, compatibility["strategy"], "compatibility.strategy")
	if strategy["fail-fast"] != false {
		t.Errorf("compatibility fail-fast = %#v, want false", strategy["fail-fast"])
	}
	for _, name := range []string{"formatting", "core", "tests", "analysis", "compatibility"} {
		job := mapping(t, jobs[name], name)
		if job["if"] != "${{ needs.preflight.outputs.has-go == 'true' }}" {
			t.Errorf("Go-only job %q if = %#v, want validated preflight capability", name, job["if"])
		}
	}
	for _, name := range []string{"evidence", "gate"} {
		job := mapping(t, jobs[name], name)
		if job["if"] != "${{ always() }}" {
			t.Errorf("job %q if = %#v, want always()", name, job["if"])
		}
	}
	gate := mapping(t, jobs["gate"], "gate")
	if gate["name"] != "gate" {
		t.Errorf("gate name = %#v, want gate", gate["name"])
	}
	assertCompatibilityGateContract(t, gate)
	codeql := mapping(t, jobs["codeql"], "codeql")
	codeqlPermissions := mapping(t, codeql["permissions"], "codeql.permissions")
	if codeqlPermissions["contents"] != "read" || codeqlPermissions["security-events"] != "write" {
		t.Errorf("CodeQL permissions = %#v", codeqlPermissions)
	}
	for _, rawStep := range sequence(t, codeql["steps"], "codeql steps") {
		step := mapping(t, rawStep, "codeql step")
		if step["name"] != "Bootstrap policy CLI" {
			continue
		}
		with := mapping(t, step["with"], "codeql bootstrap inputs")
		if with["go-version"] != "1.26.7" {
			t.Errorf("CodeQL bootstrap Go version = %#v, want previous supported 1.26.7", with["go-version"])
		}
		return
	}
	t.Error("CodeQL has no policy CLI bootstrap step")
}

func assertCompatibilityGateContract(t *testing.T, gate map[string]any) {
	t.Helper()
	for _, rawStep := range sequence(t, gate["steps"], "gate steps") {
		step := mapping(t, rawStep, "gate step")
		if step["name"] != "Enforce aggregate result" {
			continue
		}
		environment := mapping(t, step["env"], "compatibility gate env")
		if environment["EXPECTED_PROFILE"] != "${{ needs.preflight.outputs.profile }}" {
			t.Errorf("compatibility gate profile = %#v", environment["EXPECTED_PROFILE"])
		}
		if environment["HAS_GO"] != "${{ needs.preflight.outputs.has-go }}" {
			t.Errorf("compatibility gate has-go = %#v", environment["HAS_GO"])
		}
		run, _ := step["run"].(string)
		profileBranch := `if [[ "$HAS_GO" == false ]]; then
  [[ "$COMPATIBILITY_RESULT" == skipped ]]
else
  [[ "$COMPATIBILITY_RESULT" == success ]]
fi`
		if !strings.Contains(run, profileBranch) {
			t.Errorf("compatibility gate profile branch = %q", run)
		}
		return
	}
	t.Error("gate has no aggregate enforcement step")
}

func assertGoPlanWorkflowContract(t *testing.T, jobs map[string]any, text string) {
	t.Helper()
	for _, forbidden := range []string{
		"inputs.profile", "inputs.go-version", "inputs.previous-go-version",
		"go build ./...", "go test ./...", "go vet ./...",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("standard workflow reconstructs policy with %q", forbidden)
		}
	}
	for _, required := range []string{
		`"$CLI" go-plan`, "go-plan.json", "github-ci-plan", "1.27.0", "1.26.7",
		`bash "$CENTRAL_DIR/scripts/run-go-group.sh" compatibility`,
		`bash "$CENTRAL_DIR/scripts/run-go-group.sh" codeql-build`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("standard workflow is missing typed-plan contract %q", required)
		}
	}
	for _, name := range []string{"formatting", "core", "tests", "analysis", "compatibility"} {
		job := mapping(t, jobs[name], name)
		if job["needs"] != "preflight" {
			t.Errorf("Go job %q needs = %#v, want preflight", name, job["needs"])
		}
	}
}

func assertBootstrapNetworkAccess(t *testing.T, jobs map[string]any) {
	t.Helper()
	for name, raw := range jobs {
		job := mapping(t, raw, "job "+name)
		steps := sequence(t, job["steps"], "job "+name+" steps")
		usesBootstrap := false
		allowlist := ""
		for _, rawStep := range steps {
			step := mapping(t, rawStep, "job "+name+" step")
			uses, _ := step["uses"].(string)
			usesBootstrap = usesBootstrap || uses == "./github-ci/actions/bootstrap"
			if strings.HasPrefix(uses, "step-security/harden-runner@") {
				with := mapping(t, step["with"], "job "+name+" Harden Runner inputs")
				allowlist, _ = with["allowed-endpoints"].(string)
			}
		}
		if !usesBootstrap {
			continue
		}
		for _, endpoint := range []string{"go.dev:443", "proxy.golang.org:443", "sum.golang.org:443", "storage.googleapis.com:443"} {
			if !strings.Contains(allowlist, endpoint) {
				t.Errorf("job %q bootstraps Go without allowing %s", name, endpoint)
			}
		}
	}
}

func assertScannerRuntimeContracts(t *testing.T, jobs map[string]any) {
	t.Helper()
	dependencyReviewAllowlist := hardenRunnerAllowlist(t, jobs, "dependency-review")
	if !strings.Contains(dependencyReviewAllowlist, "api.deps.dev:443") {
		t.Error("dependency-review job does not allow its dependency metadata endpoint")
	}

	analysisAllowlist := hardenRunnerAllowlist(t, jobs, "analysis")
	if !strings.Contains(analysisAllowlist, "vuln.go.dev:443") {
		t.Error("analysis job does not allow the govulncheck vulnerability database")
	}

	for _, name := range []string{"security", "repository"} {
		allowlist := hardenRunnerAllowlist(t, jobs, name)
		if !strings.Contains(allowlist, "production.cloudfront.docker.com:443") {
			t.Errorf("job %q does not allow Docker's image delivery endpoint", name)
		}
		if strings.Contains(allowlist, "production.cloudflare.docker.com:443") {
			t.Errorf("job %q allows the invalid Docker delivery endpoint", name)
		}
	}

	repository := mapping(t, jobs["repository"], "repository")
	steps := sequence(t, repository["steps"], "repository steps")
	foundPython := false
	for _, rawStep := range steps {
		step := mapping(t, rawStep, "repository step")
		uses, _ := step["uses"].(string)
		if !strings.HasPrefix(uses, "actions/setup-python@") {
			continue
		}
		with := mapping(t, step["with"], "setup-python inputs")
		foundPython = with["python-version"] == "3.11"
	}
	if !foundPython {
		t.Error("repository scanners do not pin Python 3.11 for locked wheels")
	}

	scorecard := mapping(t, jobs["scorecard"], "scorecard")
	scorecardSteps := sequence(t, scorecard["steps"], "scorecard steps")
	allowlist := hardenRunnerAllowlist(t, jobs, "scorecard")
	foundRelativeReport := false
	for _, rawStep := range scorecardSteps {
		step := mapping(t, rawStep, "scorecard step")
		uses, _ := step["uses"].(string)
		if strings.HasPrefix(uses, "ossf/scorecard-action@") {
			with := mapping(t, step["with"], "scorecard inputs")
			foundRelativeReport = with["results_file"] == "scorecard.sarif"
		}
	}
	for _, endpoint := range []string{
		"api.deps.dev:443", "api.osv.dev:443",
		"oss-fuzz-build-logs.storage.googleapis.com:443", "www.bestpractices.dev:443",
	} {
		if !strings.Contains(allowlist, endpoint) {
			t.Errorf("scorecard job does not allow %s", endpoint)
		}
	}
	if !foundRelativeReport {
		t.Error("Scorecard does not use a container-portable relative result path")
	}
}

func hardenRunnerAllowlist(t *testing.T, jobs map[string]any, name string) string {
	t.Helper()
	job := mapping(t, jobs[name], name)
	steps := sequence(t, job["steps"], name+" steps")
	for _, rawStep := range steps {
		step := mapping(t, rawStep, name+" step")
		uses, _ := step["uses"].(string)
		if !strings.HasPrefix(uses, "step-security/harden-runner@") {
			continue
		}
		with := mapping(t, step["with"], name+" Harden Runner inputs")
		allowlist, _ := with["allowed-endpoints"].(string)
		return allowlist
	}
	t.Fatalf("job %q has no Harden Runner step", name)
	return ""
}

func assertWorkflowTextContracts(t *testing.T, text string) {
	t.Helper()
	if !strings.Contains(text, "retention-days: 7") {
		t.Error("workflow has no seven-day evidence retention")
	}
	if strings.Contains(text, "continue-on-error:") {
		t.Error("workflow uses continue-on-error")
	}
	if !strings.Contains(text, "upload: always") || strings.Contains(text, "upload: never") {
		t.Error("CodeQL results are not uploaded to code scanning")
	}
	assertImmutableUses(t, text)
}

func TestGolangCILintConfigContract(t *testing.T) {
	data, err := os.ReadFile("../../configs/golangci.yml")
	if err != nil {
		t.Fatalf("read golangci-lint config: %v", err)
	}
	var configuration map[string]any
	if err := yaml.Unmarshal(data, &configuration); err != nil {
		t.Fatalf("decode golangci-lint config: %v", err)
	}

	linters := mapping(t, configuration["linters"], "linters")
	if linters["default"] != "none" {
		t.Errorf("linters.default = %#v, want none", linters["default"])
	}
	enabled := sequence(t, linters["enable"], "linters.enable")
	if len(enabled) != 74 {
		t.Errorf("enabled linter count = %d, want 74", len(enabled))
	}

	settings := mapping(t, linters["settings"], "linters.settings")
	cyclop := mapping(t, settings["cyclop"], "linters.settings.cyclop")
	if cyclop["max-complexity"] != 20 {
		t.Errorf("cyclop max-complexity = %#v, want 20", cyclop["max-complexity"])
	}
	gocognit := mapping(t, settings["gocognit"], "linters.settings.gocognit")
	if gocognit["min-complexity"] != 30 {
		t.Errorf("gocognit min-complexity = %#v, want 30", gocognit["min-complexity"])
	}
	goconst := mapping(t, settings["goconst"], "linters.settings.goconst")
	if goconst["ignore-tests"] != true {
		t.Errorf("goconst ignore-tests = %#v, want true", goconst["ignore-tests"])
	}
	depguard := mapping(t, settings["depguard"], "linters.settings.depguard")
	rules := mapping(t, depguard["rules"], "linters.settings.depguard.rules")
	mainRule := mapping(t, rules["main"], "linters.settings.depguard.rules.main")
	if _, exists := mainRule["allow"]; exists {
		t.Error("depguard main rule has a repository-specific allowlist")
	}
	if len(sequence(t, mainRule["deny"], "linters.settings.depguard.rules.main.deny")) == 0 {
		t.Error("depguard main rule has no denied dependencies")
	}
	recvcheck := mapping(t, settings["recvcheck"], "linters.settings.recvcheck")
	if !slices.Equal(sequence(t, recvcheck["exclusions"], "linters.settings.recvcheck.exclusions"), []any{"*.UnmarshalJSON"}) {
		t.Errorf("recvcheck exclusions = %#v", recvcheck["exclusions"])
	}

	exclusions := mapping(t, linters["exclusions"], "linters.exclusions")
	if exclusions["generated"] != "strict" || exclusions["warn-unused"] != true {
		t.Errorf("linters.exclusions = %#v, want strict generation and unused warnings", exclusions)
	}
	exclusionRules := sequence(t, exclusions["rules"], "linters.exclusions.rules")
	if len(exclusionRules) != 1 {
		t.Fatalf("exclusion rule count = %d, want 1", len(exclusionRules))
	}
	testRule := mapping(t, exclusionRules[0], "linters.exclusions.rules[0]")
	if testRule["path"] != `_test\.go` {
		t.Errorf("test exclusion path = %#v", testRule["path"])
	}
	excludedLinters := sequence(t, testRule["linters"], "linters.exclusions.rules[0].linters")
	if !slices.Equal(excludedLinters, []any{"gosec"}) {
		t.Errorf("test exclusions = %#v, want gosec", excludedLinters)
	}

	issues := mapping(t, configuration["issues"], "issues")
	if issues["max-issues-per-linter"] != 0 || issues["max-same-issues"] != 0 {
		t.Errorf("issues limits = %#v, want unlimited reporting", issues)
	}
}

func TestScannerInventory(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/go.yml")
	if err != nil {
		t.Fatalf("read Go workflow: %v", err)
	}
	text := string(data)
	identities := []string{
		"codeql/actions", "codeql/go", "dependency-review/changes",
		"gitleaks/content", "osv-scanner/dependencies", "trivy/filesystem",
		"syft/sbom", "grype/sbom", "semgrep/source", "actionlint/workflows",
		"zizmor/workflows", "scorecard/repository", "checkov/infrastructure",
		"hadolint/dockerfiles", "shellcheck/scripts", "shfmt/scripts",
		"yamllint/documents", "markdownlint/documents", "json/documents",
		"license/dependencies", "apidiff/public-api",
	}
	for _, identity := range identities {
		if !strings.Contains(text, identity) {
			t.Errorf("scanner identity %q is missing", identity)
		}
	}
	for _, query := range []string{"security-extended", "security-and-quality"} {
		if !strings.Contains(text, query) {
			t.Errorf("CodeQL query suite %q is missing", query)
		}
	}
	if strings.Contains(text, "egress-policy: audit") {
		t.Error("workflow contains audit-only runner egress")
	}
	if !strings.Contains(text, "egress-policy: block") || !strings.Contains(text, "allowed-endpoints:") {
		t.Error("workflow does not enforce explicit block-mode egress")
	}
}

func TestDeepWorkflowContract(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/deep.yml")
	if err != nil {
		t.Fatalf("read deep workflow: %v", err)
	}
	text := string(data)
	for _, required := range []string{
		"preflight:", "portability:", "fuzz-benchmark:", "mutation:", "history-refresh:",
		"go-plan.json", "github-ci-deep-plan", "scripts/run-deep-go.sh\" portability",
		"scripts/run-deep-go.sh\" fuzz-benchmark", "scripts/run-deep-go.sh\" mutation-context",
		"gitleaks git", "go mod edit -json", `go list -m -u -json "${dependencies[@]}"`,
		"1.27.0", "1.26.7", "ubuntu-latest", "macos-latest", "windows-latest",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("deep workflow is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"services:", "postgres:", "redis:", "POSTGRES_DSN", "REDIS_ADDR", "-tags integration",
		"inputs.profile", "inputs.go-version", "inputs.previous-go-version",
		"go build ./...", "go test ./...", "go vet ./...", "go list ./...",
		"egress-policy: audit", "go list -m -u -json all", "== skipped",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("deep workflow contains forbidden %q", forbidden)
		}
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("decode deep workflow: %v", err)
	}
	on := mapping(t, workflow["on"], "deep on")
	inputs := mapping(t, mapping(t, on["workflow_call"], "deep workflow_call")["inputs"], "deep inputs")
	if len(inputs) != 2 || inputs["config-path"] == nil || inputs["fuzz-time"] == nil {
		t.Errorf("deep inputs = %#v, want config-path and fuzz-time", inputs)
	}
	jobs := mapping(t, workflow["jobs"], "deep jobs")
	if _, exists := jobs["services"]; exists {
		t.Error("deep workflow still defines a central services job")
	}
	assertDeepWorkflowTimeouts(t, jobs)
	for _, name := range []string{"portability", "fuzz-benchmark", "mutation", "history-refresh"} {
		job := mapping(t, jobs[name], "deep "+name)
		if job["needs"] != "preflight" {
			t.Errorf("deep job %q needs = %#v, want preflight", name, job["needs"])
		}
	}
	for _, name := range []string{"preflight", "portability", "fuzz-benchmark", "mutation", "history-refresh"} {
		job := mapping(t, jobs[name], "deep "+name)
		assertDualCheckout(t, job)
		assertNoExpressionsInRun(t, name, job)
	}
	gate := mapping(t, jobs["gate"], "deep gate")
	needs := sequence(t, gate["needs"], "deep gate needs")
	if !slices.Equal(needs, []any{"preflight", "portability", "fuzz-benchmark", "mutation", "history-refresh"}) {
		t.Errorf("deep gate needs = %#v", needs)
	}
	for _, assertion := range []string{
		`[[ "$PREFLIGHT_RESULT" == success ]]`,
		`[[ "$FUZZ_RESULT" == success ]]`,
		`[[ "$HISTORY_RESULT" == success ]]`,
		`[[ "$MUTATION_RESULT" == success ]]`,
		`[[ "$PORTABILITY_RESULT" == success ]]`,
	} {
		if !strings.Contains(text, assertion) {
			t.Errorf("deep gate is missing %q", assertion)
		}
	}
	assertImmutableUses(t, text)
}

func TestDeepExecutorContract(t *testing.T) {
	data, err := os.ReadFile("../../scripts/run-deep-go.sh")
	if err != nil {
		t.Fatalf("read deep executor: %v", err)
	}
	text := string(data)
	for _, required := range []string{
		`load_go_invocation "$GO_PLAN_PATH" "$index" build`,
		`load_go_invocation "$GO_PLAN_PATH" "$index" test`,
		`load_go_invocation "$GO_PLAN_PATH" "$index" gopls`,
		`^Fuzz[[:alnum:]_]*$`, `-fuzz="^${target}$"`, `-fuzztime="$FUZZ_TIME"`,
		`--workers 4`, `--test-cpu 1`, `--timeout-coefficient 100`, `--output-statuses lctvs`, `--arithmetic-base`,
		`--conditionals-boundary`, `--conditionals-negation`, `--increment-decrement`,
		`--invert-assignments`, `--invert-bitwise`, `--invert-bwassign`,
		`--invert-logical`, `--invert-loopctrl`, `--invert-negatives`,
		`--remove-self-assignments`, `--output "$report" "$package"`,
		`for package_index in "${!concrete_packages[@]}"`,
		`validate-gremlins --report "$report" --module "$module_path"`,
		`validate-gremlins-no-results --log "$transcript" --module "$module_path" --output "$evidence"`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("deep executor is missing %q", required)
		}
	}
	if strings.Contains(text, "./...") {
		t.Error("deep executor reconstructs a root package scope")
	}
	if strings.Contains(text, "--integration") {
		t.Error("deep executor reruns the entire module test suite for each package mutation")
	}
	if count := strings.Count(text, `for index in "${!GO_PLAN_MODULE_PATHS[@]}"`); count != 3 {
		t.Errorf("deep executor module loops = %d, want 3", count)
	}
}

func TestReleaseWorkflowProducesEvidenceWithoutPublishing(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	text := string(data)
	for _, required := range []string{
		"release-manifest.json",
		"SHA256SUMS",
		"sbom.spdx.json",
		"sbom.cdx.json",
		"attest-build-provenance",
		"include-callers:",
		"acceptance-required:",
		"default: false",
		`default: "1.27.0"`,
		`ref: ${{ inputs.tag || github.ref }}`,
		`INCLUDE_CALLERS: ${{ inputs.include-callers }}`,
		`ACCEPTANCE_REQUIRED: ${{ inputs.acceptance-required }}`,
		`REPOSITORY: ${{ github.repository }}`,
		`WORKFLOW_REPOSITORY: ${{ job.workflow_repository }}`,
		`WORKFLOW_SHA: ${{ job.workflow_sha }}`,
		`source_sha=$(git -C "$SOURCE_DIR" rev-parse HEAD)`,
		`[[ "$source_sha" == "$tagged_sha" ]]`,
		`[[ "$tagged_sha" == "$EVENT_SHA" ]]`,
		`if [[ "$INCLUDE_CALLERS" == "true" ]]`,
		`if [[ "$ACCEPTANCE_REQUIRED" == "true" ]]`,
		`[[ "$REPOSITORY" == "$WORKFLOW_REPOSITORY" ]]`,
		`[[ "$WORKFLOW_SHA" == "$tagged_sha" ]]`,
		`verify-acceptance-record --record "$ACCEPTANCE_RECORD" --expected-sha "$tagged_sha"`,
		`--asset dist/release-acceptance.json`,
		"github-ci-govern",
		"render-callers",
		`--workflow-sha "$tagged_sha"`,
		`--subject-sha "$tagged_sha"`,
		"--asset dist/github-ci.yaml",
		"--asset dist/github-ci.yml",
		"--asset dist/github-ci-deep.yml",
		"--asset dist/github-ci-release.yml",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("release workflow is missing %q", required)
		}
	}
	for _, forbidden := range []string{"gh release", "git tag", "egress-policy: audit", "REF_TYPE", `if [[ "$REF_TYPE" == "tag" ]]`} {
		if strings.Contains(text, forbidden) {
			t.Errorf("release workflow contains forbidden %q", forbidden)
		}
	}
	if strings.Contains(text, `--workflow-sha "$EVENT_SHA"`) {
		t.Error("release workflow pins callers to the consumer commit instead of its own workflow commit")
	}
	if strings.Contains(text, `--subject-sha "$EVENT_SHA"`) {
		t.Error("release workflow binds manually dispatched evidence to the dispatch branch instead of the requested tag")
	}
	assertImmutableUses(t, text)
}

func TestRepositoryReleaseCallerIncludesPinnedCallers(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/release-evidence.yml")
	if err != nil {
		t.Fatalf("read repository release caller: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "include-callers: true") {
		t.Error("repository release caller does not include SHA-pinned caller assets")
	}
	for _, required := range []string{
		"actions: read", "acceptance:", "release-candidate.yml", "head_sha", "status=success",
		"go-version: 1.27.0",
		"github-ci-release-acceptance", "verify-acceptance-record", "acceptance-required: true", "needs: acceptance",
		`WORKFLOW_REPOSITORY: ${{ job.workflow_repository }}`,
		`WORKFLOW_SHA: ${{ job.workflow_sha }}`,
		`[[ "$REPOSITORY" == "$WORKFLOW_REPOSITORY" ]]`,
		`[[ "$WORKFLOW_SHA" == "$tagged_sha" ]]`,
		`[[ "$tagged_sha" == "$EVENT_SHA" ]]`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("repository release caller is missing %q", required)
		}
	}
	if strings.Contains(text, "REF_TYPE") || strings.Contains(text, `if [[ "$REF_TYPE" == "tag" ]]`) {
		t.Error("repository release caller permits branch-dispatched evidence for a different tag commit")
	}
	assertImmutableUses(t, text)
}

func TestReleaseCandidateRequiresLocalAndExternalAcceptance(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/release-candidate.yml")
	if err != nil {
		t.Fatalf("read release candidate workflow: %v", err)
	}
	text := string(data)
	for _, required := range []string{
		"workflow_dispatch:", "canary-repository:", "standard-run-id:", "deep-run-id:", "fork-run-id:",
		"go-version: 1.27.0",
		"local-standard:", "uses: ./.github/workflows/go.yml", "local-deep:", "uses: ./.github/workflows/deep.yml",
		"verify-acceptance", `--candidate-sha "$CANDIDATE_SHA"`, "github-ci-release-acceptance", "if-no-files-found: error",
		"needs: [local-standard, local-deep, verify]", "RESULT_STANDARD", "RESULT_DEEP", "RESULT_VERIFY",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("release candidate workflow is missing %q", required)
		}
	}
	for _, forbidden := range []string{"git tag", "gh release", "pull-requests: write", "contents: write"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("release candidate workflow contains forbidden %q", forbidden)
		}
	}
	assertImmutableUses(t, text)
}

func TestGeneratedCallerHasRequiredEvents(t *testing.T) {
	data, err := os.ReadFile("../../templates/callers/generated/github-ci.yml")
	if err != nil {
		t.Fatalf("read caller: %v", err)
	}
	text := string(data)
	for _, event := range []string{"pull_request:", "push:", "merge_group:", "workflow_dispatch:"} {
		if !strings.Contains(text, event) {
			t.Errorf("caller missing %s", event)
		}
	}
	if strings.Contains(text, "paths:") {
		t.Error("required caller contains a workflow-level path filter")
	}
}

func TestGeneratedReleaseCallerForwardsManualTag(t *testing.T) {
	data, err := os.ReadFile("../../templates/callers/generated/github-ci-release.yml")
	if err != nil {
		t.Fatalf("read release caller: %v", err)
	}
	text := string(data)
	for _, required := range []string{
		"inputs:",
		"tag:",
		"required: true",
		"type: string",
		`tag: ${{ inputs.tag }}`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("release caller is missing %q", required)
		}
	}
}

func TestCompositeActionsArePinnedAndNonPrivileged(t *testing.T) {
	for _, name := range []string{"../../actions/bootstrap/action.yml", "../../actions/record/action.yml"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(data)
		assertImmutableUses(t, text)
		if strings.Contains(text, "sudo ") || strings.Contains(text, "secrets.") {
			t.Errorf("%s requests privileged or secret access", name)
		}
		for _, commandFile := range []string{"GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT"} {
			if strings.Contains(text, commandFile) {
				t.Errorf("%s writes the %s command file", name, commandFile)
			}
		}
	}
}

func TestActionlintConfigAllowsCurrentWorkflowIdentityContext(t *testing.T) {
	data, err := os.ReadFile("../../.github/actionlint.yaml")
	if err != nil {
		t.Fatalf("read actionlint config: %v", err)
	}
	want := "paths:\n" +
		"  .github/workflows/**/*.{yml,yaml}:\n" +
		"    ignore:\n" +
		"      - 'property \"workflow_(repository|sha)\" is not defined in object type'\n"
	if string(data) != want {
		t.Fatalf("actionlint config = %q, want narrow workflow identity exception", data)
	}
}

func assertDualCheckout(t *testing.T, job map[string]any) {
	t.Helper()
	steps := sequence(t, job["steps"], "steps")
	consumer := false
	central := false
	for _, raw := range steps {
		step := mapping(t, raw, "step")
		uses, _ := step["uses"].(string)
		if strings.HasPrefix(uses, "actions/checkout@") {
			with := mapping(t, step["with"], "checkout.with")
			if with["path"] == "source" {
				consumer = true
			}
			if with["repository"] == "${{ job.workflow_repository }}" && with["ref"] == "${{ job.workflow_sha }}" && with["path"] == "github-ci" {
				central = true
			}
		}
	}
	if !consumer || !central {
		t.Errorf("job does not have consumer and defining-workflow-bound helper checkouts")
	}
}

func assertNoExpressionsInRun(t *testing.T, jobName string, job map[string]any) {
	t.Helper()
	steps, ok := job["steps"].([]any)
	if !ok {
		return
	}
	for _, raw := range steps {
		step := mapping(t, raw, "step")
		if run, ok := step["run"].(string); ok && strings.Contains(run, "${{") {
			t.Errorf("job %q interpolates an expression in run: %q", jobName, run)
		}
	}
}

func assertImmutableUses(t *testing.T, text string) {
	t.Helper()
	immutable := regexp.MustCompile(`^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}$`)
	for line := range strings.SplitSeq(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "uses:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "uses:"))
		if strings.HasPrefix(value, "./") {
			continue
		}
		if !immutable.MatchString(value) {
			t.Errorf("mutable action reference %q", value)
		}
	}
}

func mapping(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	mapping, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want mapping", path, value)
	}
	return mapping
}

func sequence(t *testing.T, value any, path string) []any {
	t.Helper()
	sequence, ok := value.([]any)
	if !ok {
		t.Fatalf("%s = %#v, want sequence", path, value)
	}
	return sequence
}
