package generate

import (
	"os"
	"regexp"
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
	on := mapping(t, workflow["on"], "on")
	workflowCall := mapping(t, on["workflow_call"], "on.workflow_call")
	inputs := mapping(t, workflowCall["inputs"], "on.workflow_call.inputs")
	for _, input := range []string{"profile", "config-path", "go-version", "previous-go-version"} {
		if _, exists := inputs[input]; !exists {
			t.Errorf("workflow_call input %q is missing", input)
		}
	}
	permissions := mapping(t, workflow["permissions"], "permissions")
	if len(permissions) != 1 || permissions["contents"] != "read" {
		t.Errorf("workflow permissions = %#v, want contents: read only", permissions)
	}

	jobs := mapping(t, workflow["jobs"], "jobs")
	for _, name := range []string{"preflight", "formatting", "core", "tests", "analysis", "compatibility", "codeql", "dependency-review", "security", "supply-chain", "repository", "scorecard", "evidence", "gate"} {
		if _, exists := jobs[name]; !exists {
			t.Errorf("required job %q is missing", name)
		}
	}
	for name, raw := range jobs {
		job := mapping(t, raw, "job "+name)
		if timeout, ok := job["timeout-minutes"].(int); !ok || timeout <= 0 || timeout > 60 {
			t.Errorf("job %q timeout-minutes = %#v, want 1..60", name, job["timeout-minutes"])
		}
		assertNoExpressionsInRun(t, name, job)
	}

	preflight := mapping(t, jobs["preflight"], "preflight")
	assertDualCheckout(t, preflight)
	compatibility := mapping(t, jobs["compatibility"], "compatibility")
	strategy := mapping(t, compatibility["strategy"], "compatibility.strategy")
	if strategy["fail-fast"] != false {
		t.Errorf("compatibility fail-fast = %#v, want false", strategy["fail-fast"])
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

	text := string(data)
	if !strings.Contains(text, "retention-days: 7") {
		t.Error("workflow has no seven-day evidence retention")
	}
	if strings.Contains(text, "continue-on-error:") {
		t.Error("workflow uses continue-on-error")
	}
	assertImmutableUses(t, text)
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
			if with["repository"] == "gomaja/github-ci" && with["ref"] == "${{ github.workflow_sha }}" && with["path"] == "github-ci" {
				central = true
			}
		}
	}
	if !consumer || !central {
		t.Errorf("job does not have consumer and workflow-SHA-bound central checkouts")
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
	for _, line := range strings.Split(text, "\n") {
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
