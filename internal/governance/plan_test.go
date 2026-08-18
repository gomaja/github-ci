package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/gomaja/github-ci/internal/config"
)

func TestBuildAndApplyPlanConverges(t *testing.T) {
	t.Parallel()
	github := newFakeGitHub()
	server := httptest.NewServer(github)
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, Token: "token", APIVersion: "2026-03-10", HTTP: server.Client()}
	manifest := testGovernance()

	plan, err := BuildPlan(context.Background(), client, manifest)
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	if len(plan.Operations) < 9 {
		t.Fatalf("Operations = %v, want complete drift plan", operationKinds(plan.Operations))
	}
	if plan.ID == "" || plan.ObservedHash == "" {
		t.Fatalf("Plan identity is incomplete: %+v", plan)
	}
	second, err := BuildPlan(context.Background(), client, manifest)
	if err != nil || second.ID != plan.ID {
		t.Fatalf("second BuildPlan() = %q, %v; want %q", second.ID, err, plan.ID)
	}
	if err := Apply(context.Background(), client, manifest, plan, "wrong"); err == nil {
		t.Fatal("Apply() accepted wrong confirmation")
	}
	if err := Apply(context.Background(), client, manifest, plan, plan.ID); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	clean, err := BuildPlan(context.Background(), client, manifest)
	if err != nil {
		t.Fatalf("clean BuildPlan() error = %v", err)
	}
	if len(clean.Operations) != 0 {
		t.Fatalf("clean Operations = %v, want none", operationKinds(clean.Operations))
	}
	if github.mutations == 0 {
		t.Fatal("fake GitHub observed no mutations")
	}
}

func TestApplyRejectsConcurrentDrift(t *testing.T) {
	t.Parallel()
	github := newFakeGitHub()
	server := httptest.NewServer(github)
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
	manifest := testGovernance()
	plan, err := BuildPlan(context.Background(), client, manifest)
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}

	github.mu.Lock()
	github.repository.AllowSquashMerge = true
	github.repository.AllowMergeCommit = false
	github.repository.AllowRebaseMerge = false
	github.repository.DeleteBranchOnMerge = true
	github.repository.AllowUpdateBranch = true
	github.repository.SquashMergeCommitTitle = "COMMIT_OR_PR_TITLE"
	github.repository.SquashMergeCommitMessage = "COMMIT_MESSAGES"
	github.mu.Unlock()

	err = Apply(context.Background(), client, manifest, plan, plan.ID)
	if err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("Apply() error = %v, want stale-plan error", err)
	}
}

func TestBuildPlanRefusesUnexpectedRepositoryScope(t *testing.T) {
	t.Parallel()
	github := newFakeGitHub()
	github.repository.Fork = true
	server := httptest.NewServer(github)
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
	_, err := BuildPlan(context.Background(), client, testGovernance())
	if err == nil || !strings.Contains(err.Error(), "immutable governance scope") {
		t.Fatalf("BuildPlan() error = %v, want scope refusal", err)
	}
}

func testGovernance() config.Governance {
	return config.Governance{
		SchemaVersion: 1,
		APIVersion:    "2026-03-10",
		Owners:        []config.Owner{{Name: "gomaja", Type: "user"}},
		Defaults: config.GovernanceDefaults{
			Profile: config.ProfileGoStrict, DefaultBranch: "main", RequiredCheck: "github-ci / gate",
			PublicOnly: true, RefuseForks: true, RefuseArchived: true, RefusePrivate: true, RefuseUnexpectedOwners: true,
		},
		Repositories: []config.Repository{{Name: "example", Owner: "gomaja", EnforceCaller: false}},
	}
}

type fakeGitHub struct {
	mu          sync.Mutex
	repository  repositoryState
	actions     actionsState
	workflow    workflowState
	selected    selectedActionsState
	alerts      bool
	fixes       enabledState
	reporting   enabledState
	rulesets    map[int64]rulesetPayload
	nextRuleset int64
	mutations   int
}

func newFakeGitHub() *fakeGitHub {
	github := &fakeGitHub{
		actions:     actionsState{Enabled: true, AllowedActions: "all", SHAPinningRequired: false},
		workflow:    workflowState{DefaultPermissions: "write", CanApprove: true},
		selected:    selectedActionsState{PatternsAllowed: []string{}},
		fixes:       enabledState{Enabled: false},
		reporting:   enabledState{Enabled: false},
		rulesets:    make(map[int64]rulesetPayload),
		nextRuleset: 2,
	}
	github.repository.Name = "example"
	github.repository.Owner.Login = "gomaja"
	github.repository.DefaultBranch = "main"
	legacy := branchRuleset(config.Repository{})
	legacy.Name = "main branch ruleset"
	for index := range legacy.Rules {
		if legacy.Rules[index].Type == "copilot_code_review" {
			legacy.Rules[index].Parameters["review_on_push"] = false
		}
	}
	github.rulesets[1] = legacy
	return github
}

func (github *fakeGitHub) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	github.mu.Lock()
	defer github.mu.Unlock()
	writer.Header().Set("Content-Type", "application/json")
	const base = "/repos/gomaja/example"
	path := request.URL.Path

	switch {
	case path == base:
		github.serveRepository(writer, request)
	case strings.HasPrefix(path, base+"/actions/permissions"):
		github.serveActionsPermissions(writer, request)
	case path == base+"/vulnerability-alerts":
		github.serveVulnerabilityAlerts(writer, request)
	case path == base+"/automated-security-fixes":
		github.serveEnabledSetting(writer, request, &github.fixes)
	case path == base+"/private-vulnerability-reporting":
		github.serveEnabledSetting(writer, request, &github.reporting)
	case path == base+"/rulesets":
		github.serveRulesets(writer, request)
	case strings.HasPrefix(path, base+"/rulesets/"):
		github.serveRuleset(writer, request)
	default:
		http.Error(writer, fmt.Sprintf(`{"message":"unhandled %s %s"}`, request.Method, path), http.StatusNotFound)
	}
}

func (github *fakeGitHub) serveRepository(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		writeFakeJSON(writer, github.repository)
		return
	}
	if request.Method != http.MethodPatch {
		http.Error(writer, `{"message":"method"}`, http.StatusMethodNotAllowed)
		return
	}
	var body map[string]any
	decodeFakeJSON(writer, request, &body)
	if _, found := body["security_and_analysis"]; found {
		github.repository.SecurityAndAnalysis.SecretScanning.Status = "enabled"
		github.repository.SecurityAndAnalysis.PushProtection.Status = "enabled"
	} else {
		github.repository.AllowSquashMerge = true
		github.repository.AllowMergeCommit = false
		github.repository.AllowRebaseMerge = false
		github.repository.DeleteBranchOnMerge = true
		github.repository.AllowUpdateBranch = true
		github.repository.SquashMergeCommitTitle = "COMMIT_OR_PR_TITLE"
		github.repository.SquashMergeCommitMessage = "COMMIT_MESSAGES"
	}
	github.mutated(writer)
}

func (github *fakeGitHub) serveActionsPermissions(writer http.ResponseWriter, request *http.Request) {
	const base = "/repos/gomaja/example/actions/permissions"
	switch request.URL.Path {
	case base:
		github.serveMutableJSON(writer, request, &github.actions)
	case base + "/workflow":
		github.serveMutableJSON(writer, request, &github.workflow)
	case base + "/selected-actions":
		if request.Method == http.MethodGet && github.actions.AllowedActions != "selected" {
			http.Error(writer, `{"message":"Conflict"}`, http.StatusConflict)
			return
		}
		github.serveMutableJSON(writer, request, &github.selected)
	default:
		http.NotFound(writer, request)
	}
}

func (github *fakeGitHub) serveMutableJSON(writer http.ResponseWriter, request *http.Request, value any) {
	switch request.Method {
	case http.MethodGet:
		writeFakeJSON(writer, value)
	case http.MethodPut:
		decodeFakeJSON(writer, request, value)
		github.mutated(writer)
	default:
		http.Error(writer, `{"message":"method"}`, http.StatusMethodNotAllowed)
	}
}

func (github *fakeGitHub) serveVulnerabilityAlerts(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodPut {
		github.alerts = true
		github.mutated(writer)
		return
	}
	if request.Method == http.MethodGet && github.alerts {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if request.Method == http.MethodGet {
		http.Error(writer, `{"message":"Not Found"}`, http.StatusNotFound)
		return
	}
	http.Error(writer, `{"message":"method"}`, http.StatusMethodNotAllowed)
}

func (github *fakeGitHub) serveEnabledSetting(writer http.ResponseWriter, request *http.Request, setting *enabledState) {
	if request.Method == http.MethodGet {
		writeFakeJSON(writer, setting)
		return
	}
	if request.Method == http.MethodPut {
		*setting = enabledState{Enabled: true}
		github.mutated(writer)
		return
	}
	http.Error(writer, `{"message":"method"}`, http.StatusMethodNotAllowed)
}

func (github *fakeGitHub) serveRulesets(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		summaries := make([]rulesetSummary, 0, len(github.rulesets))
		for id, payload := range github.rulesets {
			summaries = append(summaries, rulesetSummary{ID: id, Name: payload.Name, Target: payload.Target})
		}
		slices.SortFunc(summaries, func(left, right rulesetSummary) int { return int(left.ID - right.ID) })
		writeFakeJSON(writer, summaries)
		return
	}
	if request.Method == http.MethodPost {
		var payload rulesetPayload
		decodeFakeJSON(writer, request, &payload)
		github.rulesets[github.nextRuleset] = payload
		github.nextRuleset++
		github.mutated(writer)
		return
	}
	http.Error(writer, `{"message":"method"}`, http.StatusMethodNotAllowed)
}

func (github *fakeGitHub) serveRuleset(writer http.ResponseWriter, request *http.Request) {
	var id int64
	if _, err := fmt.Sscanf(request.URL.Path, "/repos/gomaja/example/rulesets/%d", &id); err != nil {
		http.Error(writer, `{"message":"bad id"}`, http.StatusBadRequest)
		return
	}
	switch request.Method {
	case http.MethodGet:
		payload, found := github.rulesets[id]
		if !found {
			http.Error(writer, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		writeFakeJSON(writer, payload)
	case http.MethodPut:
		var payload rulesetPayload
		decodeFakeJSON(writer, request, &payload)
		github.rulesets[id] = payload
		github.mutated(writer)
	case http.MethodDelete:
		delete(github.rulesets, id)
		github.mutated(writer)
	default:
		http.Error(writer, `{"message":"method"}`, http.StatusMethodNotAllowed)
	}
}

func (github *fakeGitHub) mutated(writer http.ResponseWriter) {
	github.mutations++
	writer.WriteHeader(http.StatusNoContent)
}

func writeFakeJSON(writer http.ResponseWriter, value any) {
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		panic(err)
	}
}

func decodeFakeJSON(writer http.ResponseWriter, request *http.Request, value any) {
	if err := json.NewDecoder(request.Body).Decode(value); err != nil {
		http.Error(writer, `{"message":"bad json"}`, http.StatusBadRequest)
	}
}

func operationKinds(operations []Operation) []string {
	kinds := make([]string, len(operations))
	for index, operation := range operations {
		kinds[index] = operation.Kind
	}
	return kinds
}
