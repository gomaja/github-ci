package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/github-ci/internal/config"
)

func TestMutationSensitiveGovernanceContracts(t *testing.T) {
	t.Run("retry control flow", func(t *testing.T) {
		var requests atomic.Int32
		var waits atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			if requests.Add(1) == 1 {
				http.Error(writer, "retry", http.StatusInternalServerError)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(server.Close)
		client := Client{
			BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client(),
			retryWait: func(context.Context, time.Duration) error {
				waits.Add(1)
				return nil
			},
		}
		status, err := client.do(context.Background(), http.MethodGet, "/repos/gomaja/example", nil, nil)
		if err != nil || status != http.StatusNoContent || requests.Load() != 2 || waits.Load() != 1 {
			t.Fatalf("do() = (%d, %v), requests = %d, waits = %d", status, err, requests.Load(), waits.Load())
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := (Client{}).waitForRetry(ctx, time.Hour); !errors.Is(err, context.Canceled) {
			t.Fatalf("default wait error = %v, want context cancellation", err)
		}
	})

	t.Run("retry boundaries", func(t *testing.T) {
		tests := []struct {
			status  int
			method  string
			attempt int
			want    bool
		}{
			{status: http.StatusOK, method: http.MethodGet, attempt: 0, want: false},
			{status: 499, method: http.MethodGet, attempt: 0, want: false},
			{status: http.StatusTooManyRequests, method: http.MethodGet, attempt: 0, want: true},
			{status: http.StatusInternalServerError, method: http.MethodGet, attempt: 0, want: true},
			{status: http.StatusInternalServerError, method: http.MethodGet, attempt: 2, want: false},
			{status: http.StatusInternalServerError, method: http.MethodPost, attempt: 0, want: false},
		}
		for _, test := range tests {
			if got := shouldRetry(test.status, test.method, test.attempt); got != test.want {
				t.Fatalf("shouldRetry(%d, %q, %d) = %t, want %t", test.status, test.method, test.attempt, got, test.want)
			}
		}
	})

	t.Run("ruleset scope", func(t *testing.T) {
		base := rulesetPayload{Target: "branch", Conditions: rulesetConditions{RefName: refCondition{Include: []string{"~DEFAULT_BRANCH"}}}}
		if !sameRulesetScope(base, base) {
			t.Fatal("sameRulesetScope(equal) = false")
		}
		differentTarget := base
		differentTarget.Target = "tag"
		if sameRulesetScope(base, differentTarget) {
			t.Fatal("sameRulesetScope(different target) = true")
		}
		differentConditions := base
		differentConditions.Conditions.RefName.Include = []string{"refs/heads/other"}
		if sameRulesetScope(base, differentConditions) {
			t.Fatal("sameRulesetScope(different conditions) = true")
		}
	})

	t.Run("operation ordering", func(t *testing.T) {
		tests := []struct {
			left, right Operation
			want        int
		}{
			{left: operation("a", "actions-policy", http.MethodPut, "/z", nil), right: operation("b", "actions-policy", http.MethodPut, "/a", nil), want: -1},
			{left: operation("b", "actions-policy", http.MethodPut, "/a", nil), right: operation("a", "actions-policy", http.MethodPut, "/z", nil), want: 1},
			{left: operation("a", "repository-settings", http.MethodPatch, "/z", nil), right: operation("a", "actions-policy", http.MethodPut, "/a", nil), want: -1},
			{left: operation("a", "actions-policy", http.MethodPut, "/a", nil), right: operation("a", "repository-settings", http.MethodPatch, "/z", nil), want: 1},
		}
		for _, test := range tests {
			got := compareOperations(test.left, test.right)
			if (got < 0) != (test.want < 0) || (got > 0) != (test.want > 0) {
				t.Fatalf("compareOperations() = %d, want sign %d", got, test.want)
			}
		}
	})

	t.Run("repository profile", func(t *testing.T) {
		if got := repositoryProfile(config.ProfileGoLibrary, config.ProfileGoStrict); got != config.ProfileGoLibrary {
			t.Fatalf("repositoryProfile(configured) = %q", got)
		}
		if got := repositoryProfile("", config.ProfileGoStrict); got != config.ProfileGoStrict {
			t.Fatalf("repositoryProfile(fallback) = %q", got)
		}
	})
}

func TestGovernanceAuditAndVerifyCLI(t *testing.T) {
	github := newFakeGitHub()
	server := httptest.NewServer(github)
	t.Cleanup(server.Close)
	manifestPath := writeCLITestManifest(t)

	var stdout, stderr bytes.Buffer
	args := []string{"audit", "--manifest", manifestPath, "--base-url", server.URL, "--repository", "example"}
	if code := RunCLI(context.Background(), args, &stdout, &stderr); code != 1 {
		t.Fatalf("RunCLI(audit) = %d, stdout = %q, stderr = %q; want drift", code, stdout.String(), stderr.String())
	}
	var plan Plan
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil || len(plan.Operations) == 0 {
		t.Fatalf("audit plan = %#v, error = %v; want operations", plan, err)
	}

	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
	if err := Apply(context.Background(), client, testGovernance(), plan, plan.ID); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	args[0] = "verify"
	if code := RunCLI(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("RunCLI(verify) = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil || len(plan.Operations) != 0 {
		t.Fatalf("verify plan = %#v, error = %v; want no operations", plan, err)
	}
}

func TestGovernancePlanCLIWritesStdoutAndFile(t *testing.T) {
	server := httptest.NewServer(newFakeGitHub())
	t.Cleanup(server.Close)
	manifestPath := writeCLITestManifest(t)

	var stdout, stderr bytes.Buffer
	baseArgs := []string{"--manifest", manifestPath, "--base-url", server.URL, "--repository", "example"}
	if code := RunCLI(context.Background(), append([]string{"plan"}, baseArgs...), &stdout, &stderr); code != 0 {
		t.Fatalf("RunCLI(plan stdout) = %d, stderr = %q", code, stderr.String())
	}
	if _, err := decodePlan(stdout.Bytes()); err != nil {
		t.Fatalf("decode stdout plan: %v", err)
	}

	output := filepath.Join(t.TempDir(), "plan.json")
	args := append([]string{"plan"}, baseArgs...)
	args = append(args, "--output", output)
	if code := RunCLI(context.Background(), args, io.Discard, &stderr); code != 0 {
		t.Fatalf("RunCLI(plan file) = %d, stderr = %q", code, stderr.String())
	}
	if _, err := readPlan(output); err != nil {
		t.Fatalf("read persisted plan: %v", err)
	}

	args[len(args)-1] = t.TempDir()
	if code := RunCLI(context.Background(), args, io.Discard, &stderr); code != 2 {
		t.Fatalf("RunCLI(plan directory) = %d, want 2", code)
	}
}

func TestGovernanceApplyCLIConvergesAndReportsWriterFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		stdout io.Writer
		code   int
	}{
		{name: "success", stdout: &bytes.Buffer{}, code: 0},
		{name: "writer failure", stdout: failingWriter{}, code: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			github := newFakeGitHub()
			server := httptest.NewServer(github)
			t.Cleanup(server.Close)
			manifestPath := writeCLITestManifest(t)
			client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
			plan, err := BuildPlan(context.Background(), client, testGovernance())
			if err != nil {
				t.Fatalf("BuildPlan() error = %v", err)
			}
			planPath := filepath.Join(t.TempDir(), "plan.json")
			data, err := marshalPlan(plan)
			if err != nil {
				t.Fatalf("marshalPlan() error = %v", err)
			}
			if err := os.WriteFile(planPath, data, 0o600); err != nil {
				t.Fatalf("write plan: %v", err)
			}
			var stderr bytes.Buffer
			code := RunCLI(context.Background(), []string{
				"apply", "--manifest", manifestPath, "--base-url", server.URL,
				"--repository", "example", "--plan", planPath, "--confirm", plan.ID,
			}, test.stdout, &stderr)
			if code != test.code {
				t.Fatalf("RunCLI(apply) = %d, stderr = %q; want %d", code, stderr.String(), test.code)
			}
		})
	}
}

func TestGovernanceCLIErrors(t *testing.T) {
	manifestPath := writeCLITestManifest(t)
	failingServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "failure", http.StatusBadRequest)
	}))
	t.Cleanup(failingServer.Close)
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	invalidPlan := filepath.Join(t.TempDir(), "invalid-plan.json")
	if err := os.WriteFile(invalidPlan, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "audit flags", args: []string{"audit", "--unknown"}, want: "flag provided"},
		{name: "audit manifest", args: []string{"audit", "--manifest", missing}, want: "open governance manifest"},
		{name: "audit scope", args: []string{"audit", "--manifest", manifestPath, "--repository", "missing"}, want: "not present"},
		{name: "audit API", args: []string{"audit", "--manifest", manifestPath, "--base-url", failingServer.URL}, want: "GitHub API"},
		{name: "plan flags", args: []string{"plan", "--unknown"}, want: "flag provided"},
		{name: "plan manifest", args: []string{"plan", "--manifest", missing}, want: "open governance manifest"},
		{name: "plan scope", args: []string{"plan", "--manifest", manifestPath, "--repository", "missing"}, want: "not present"},
		{name: "plan API", args: []string{"plan", "--manifest", manifestPath, "--base-url", failingServer.URL}, want: "GitHub API"},
		{name: "apply flags", args: []string{"apply", "--unknown"}, want: "flag provided"},
		{name: "apply missing plan", args: []string{"apply", "--confirm", "id"}, want: "--plan and --confirm"},
		{name: "apply missing confirmation", args: []string{"apply", "--plan", invalidPlan}, want: "--plan and --confirm"},
		{name: "apply manifest", args: []string{"apply", "--manifest", missing, "--plan", invalidPlan, "--confirm", "id"}, want: "open governance manifest"},
		{name: "apply scope", args: []string{"apply", "--manifest", manifestPath, "--repository", "missing", "--plan", invalidPlan, "--confirm", "id"}, want: "not present"},
		{name: "apply plan", args: []string{"apply", "--manifest", manifestPath, "--plan", invalidPlan, "--confirm", "id"}, want: "plan identity"},
		{name: "render flags", args: []string{"render-callers", "--unknown"}, want: "flag provided"},
		{name: "render manifest", args: []string{"render-callers", "--manifest", missing}, want: "open governance manifest"},
		{name: "render arguments", args: []string{"render-callers", "--manifest", manifestPath, "--output", t.TempDir(), "--workflow-sha", "main"}, want: "workflow SHA"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := RunCLI(context.Background(), test.args, io.Discard, &stderr); code != 2 {
				t.Fatalf("RunCLI() = %d, stderr = %q; want 2", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.want)
			}
		})
	}
}

func TestGovernanceRenderCallersCLI(t *testing.T) {
	output := t.TempDir()
	var stderr bytes.Buffer
	if code := RunCLI(context.Background(), []string{
		"render-callers", "--manifest", writeCLITestManifest(t), "--output", output,
		"--workflow-sha", "0123456789abcdef0123456789abcdef01234567", "--repository", "example",
	}, io.Discard, &stderr); code != 0 {
		t.Fatalf("RunCLI(render-callers) = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(output, "gomaja", "example", ".github", "workflows", "github-ci.yml")); err != nil {
		t.Fatalf("stat rendered caller: %v", err)
	}
}

func TestGovernancePlanFileBoundsAndWriters(t *testing.T) {
	directory := t.TempDir()
	if _, err := readManifest(directory); err == nil || !strings.Contains(err.Error(), "read governance manifest") {
		t.Fatalf("readManifest(directory) error = %v", err)
	}
	oversizedManifest := filepath.Join(directory, "oversized.yaml")
	if err := os.WriteFile(oversizedManifest, bytes.Repeat([]byte{'x'}, maxPlanBytes+1), 0o600); err != nil {
		t.Fatalf("write oversized manifest: %v", err)
	}
	if _, err := readManifest(oversizedManifest); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("readManifest(oversized) error = %v", err)
	}
	oversizedPlan := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversizedPlan, bytes.Repeat([]byte{'x'}, maxPlanBytes+1), 0o600); err != nil {
		t.Fatalf("write oversized plan: %v", err)
	}
	if _, err := readPlan(oversizedPlan); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("readPlan(oversized) error = %v", err)
	}
	if _, err := readPlan(filepath.Join(directory, "missing.json")); err == nil || !strings.Contains(err.Error(), "read governance plan") {
		t.Fatalf("readPlan(missing) error = %v", err)
	}
	if err := writePlan(failingWriter{}, Plan{}); err == nil || !strings.Contains(err.Error(), "write governance plan") {
		t.Fatalf("writePlan(failing) error = %v", err)
	}
}

func TestGovernancePlanSizeBoundary(t *testing.T) {
	if exceedsPlanSize(maxPlanBytes) {
		t.Fatalf("exceedsPlanSize(%d) = true", maxPlanBytes)
	}
	if !exceedsPlanSize(maxPlanBytes + 1) {
		t.Fatalf("exceedsPlanSize(%d) = false", maxPlanBytes+1)
	}
}

func TestNewAPIClientTokenPrecedence(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "github-token")
	t.Setenv("GH_TOKEN", "gh-token")
	if token := newAPIClient("https://example.invalid", "2026-03-10").Token; token != "github-token" {
		t.Fatalf("Token = %q, want GITHUB_TOKEN", token)
	}
	t.Setenv("GITHUB_TOKEN", "")
	if token := newAPIClient("https://example.invalid", "2026-03-10").Token; token != "gh-token" {
		t.Fatalf("Token = %q, want GH_TOKEN", token)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func writeCLITestManifest(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "governance.yaml")
	contents := `schema-version: 2
api-version: "2026-03-10"
owners:
  - name: gomaja
    type: user
defaults:
  profile: go-strict
  default-branch: main
  required-checks: [gate / gate]
  public-only: true
  refuse-forks: true
  refuse-archived: true
  refuse-private: true
  refuse-unexpected-owners: true
repositories:
  - name: example
    enforce-caller: false
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write governance manifest: %v", err)
	}
	return path
}

func TestScopeGovernanceSelectsExactlyOneRepository(t *testing.T) {
	manifest := testGovernance()
	manifest.Repositories = append(manifest.Repositories, config.Repository{Name: "other", Owner: "gomaja"})

	scoped, err := scopeGovernance(manifest, "other")
	if err != nil {
		t.Fatalf("scopeGovernance() error = %v", err)
	}
	if len(scoped.Repositories) != 1 || scoped.Repositories[0].Name != "other" {
		t.Fatalf("scoped repositories = %#v, want only other", scoped.Repositories)
	}
	if len(manifest.Repositories) != 2 {
		t.Fatalf("scopeGovernance() mutated source manifest: %#v", manifest.Repositories)
	}
}

func TestScopeGovernanceKeepsFullManifestWhenRepositoryIsEmpty(t *testing.T) {
	manifest := testGovernance()
	scoped, err := scopeGovernance(manifest, "")
	if err != nil {
		t.Fatalf("scopeGovernance() error = %v", err)
	}
	if len(scoped.Repositories) != len(manifest.Repositories) {
		t.Fatalf("scoped repositories = %#v, want full manifest", scoped.Repositories)
	}
}

func TestScopeGovernanceRejectsUnknownRepository(t *testing.T) {
	_, err := scopeGovernance(testGovernance(), "missing")
	if err == nil || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("scopeGovernance() error = %v, want missing repository error", err)
	}
}
