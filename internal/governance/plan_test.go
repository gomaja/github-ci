package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

func TestApplyAcceptsPersistedPlan(t *testing.T) {
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
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent() error = %v", err)
	}
	var persisted Plan
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if err := Apply(context.Background(), client, manifest, persisted, persisted.ID); err != nil {
		t.Fatalf("Apply() persisted plan error = %v", err)
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

func TestApplyRejectsEachInvalidIdentityCondition(t *testing.T) {
	manifest := testGovernance()
	client := Client{BaseURL: "http://example.com", APIVersion: manifest.APIVersion}
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{
			name: "schema version",
			mutate: func(plan *Plan) {
				plan.SchemaVersion = "2"
				plan.ID = planDigest(*plan)
			},
		},
		{
			name: "identity digest",
			mutate: func(plan *Plan) {
				plan.ID = strings.Repeat("f", 64)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := validEmptyPlan(manifest.APIVersion)
			test.mutate(&plan)
			if err := Apply(context.Background(), client, manifest, plan, plan.ID); err == nil || err.Error() != "invalid governance plan identity" {
				t.Fatalf("Apply() error = %v, want invalid governance plan identity", err)
			}
		})
	}
}

func TestApplyRejectsEachAPIVersionMismatch(t *testing.T) {
	tests := []struct {
		name            string
		clientVersion   string
		manifestVersion string
	}{
		{name: "client", clientVersion: "2025-01-01", manifestVersion: "2026-03-10"},
		{name: "manifest", clientVersion: "2026-03-10", manifestVersion: "2025-01-01"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := testGovernance()
			manifest.APIVersion = test.manifestVersion
			plan := validEmptyPlan("2026-03-10")
			client := Client{BaseURL: "http://example.com", APIVersion: test.clientVersion}
			if err := Apply(context.Background(), client, manifest, plan, plan.ID); err == nil || err.Error() != "client, manifest, and plan API versions differ" {
				t.Fatalf("Apply() error = %v, want API-version mismatch", err)
			}
		})
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

func TestBranchRulesetRequiresObservedStatusWithoutCallerEnforcement(t *testing.T) {
	repository := config.Repository{ObservedRequiredCheck: "gate / gate"}
	ruleset := branchRuleset(repository)
	for _, rule := range ruleset.Rules {
		if rule.Type != "required_status_checks" {
			continue
		}
		checks, ok := rule.Parameters["required_status_checks"].([]map[string]string)
		if !ok || len(checks) != 1 || checks[0]["context"] != "gate / gate" {
			t.Fatalf("required status checks = %#v", rule.Parameters["required_status_checks"])
		}
		return
	}
	t.Fatal("branch ruleset has no required status check")
}

func TestDependabotAlertsNotFoundProducesExactEnableOperation(t *testing.T) {
	github := newFakeGitHub()
	server := httptest.NewServer(github)
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
	manifest := testGovernance()
	convergeFakeGitHub(t, client, manifest)

	github.mu.Lock()
	github.alerts = false
	github.mu.Unlock()
	plan, err := BuildPlan(context.Background(), client, manifest)
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	if len(plan.Operations) != 1 || plan.Operations[0].Kind != "dependabot-alerts" {
		t.Fatalf("Operations = %#v, want only dependabot-alerts", plan.Operations)
	}
}

func TestRulesetNameMatchTakesPrecedenceOverOverlappingScope(t *testing.T) {
	github := newFakeGitHub()
	server := httptest.NewServer(github)
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
	manifest := testGovernance()
	convergeFakeGitHub(t, client, manifest)

	github.mu.Lock()
	desired := branchRuleset(manifest.Repositories[0])
	overlapping := desired
	overlapping.Name = "overlapping branch ruleset"
	github.rulesets[1] = overlapping
	github.rulesets[3] = desired
	github.nextRuleset = 4
	github.mu.Unlock()

	plan, err := BuildPlan(context.Background(), client, manifest)
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	if len(plan.Operations) != 1 {
		t.Fatalf("Operations = %#v, want one duplicate deletion", plan.Operations)
	}
	operation := plan.Operations[0]
	if operation.Kind != "delete-overlapping-ruleset" || operation.Path != "/repos/gomaja/example/rulesets/1" {
		t.Fatalf("Operation = %#v, want deletion of lower-ID overlapping ruleset", operation)
	}
}

func TestBuildPlanCreatesEveryMissingRuleset(t *testing.T) {
	github, client, manifest := convergedFakeGitHub(t)
	github.mu.Lock()
	github.rulesets = make(map[int64]rulesetPayload)
	github.nextRuleset = 1
	github.mu.Unlock()

	plan, err := BuildPlan(context.Background(), client, manifest)
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	if len(plan.Operations) != 2 {
		t.Fatalf("Operations = %#v, want two ruleset creations", plan.Operations)
	}
	wantNames := map[string]bool{
		branchRuleset(manifest.Repositories[0]).Name: false,
		tagRuleset().Name: false,
	}
	for index, operation := range plan.Operations {
		var payload rulesetPayload
		if err := json.Unmarshal(operation.Body, &payload); err != nil {
			t.Fatalf("decode Operation[%d] body: %v", index, err)
		}
		if operation.Kind != "create-ruleset" {
			t.Fatalf("Operation[%d] = %#v, want create-ruleset", index, operation)
		}
		if _, found := wantNames[payload.Name]; !found {
			t.Fatalf("Operation[%d] ruleset name = %q, want one of %v", index, payload.Name, wantNames)
		}
		wantNames[payload.Name] = true
	}
	for name, found := range wantNames {
		if !found {
			t.Fatalf("no create-ruleset operation for %q", name)
		}
	}
}

func TestRulesetSelectionStopsAtFirstExactNameMatch(t *testing.T) {
	github, client, manifest := convergedFakeGitHub(t)
	github.mu.Lock()
	github.rulesets[3] = branchRuleset(manifest.Repositories[0])
	github.nextRuleset = 4
	github.mu.Unlock()

	plan, err := BuildPlan(context.Background(), client, manifest)
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	if len(plan.Operations) != 1 || plan.Operations[0].Kind != "delete-overlapping-ruleset" ||
		plan.Operations[0].Path != "/repos/gomaja/example/rulesets/3" {
		t.Fatalf("Operations = %#v, want deletion of later exact-name duplicate", plan.Operations)
	}
}

func TestBuildPlanDetectsEachIndependentPolicyDrift(t *testing.T) {
	tests := []struct {
		name   string
		kind   string
		mutate func(*fakeGitHub)
	}{
		{name: "workflow write permissions", kind: "workflow-permissions", mutate: func(github *fakeGitHub) { github.workflow.DefaultPermissions = "write" }},
		{name: "workflow approval", kind: "workflow-permissions", mutate: func(github *fakeGitHub) { github.workflow.CanApprove = true }},
		{name: "GitHub-owned Actions", kind: "selected-actions", mutate: func(github *fakeGitHub) { github.selected.GitHubOwnedAllowed = false }},
		{name: "verified Actions", kind: "selected-actions", mutate: func(github *fakeGitHub) { github.selected.VerifiedAllowed = true }},
		{name: "selected Action patterns", kind: "selected-actions", mutate: func(github *fakeGitHub) { github.selected.PatternsAllowed = []string{"ossf/scorecard-action@*"} }},
		{name: "secret scanning", kind: "secret-scanning", mutate: func(github *fakeGitHub) { github.repository.SecurityAndAnalysis.SecretScanning.Status = "disabled" }},
		{name: "push protection", kind: "secret-scanning", mutate: func(github *fakeGitHub) { github.repository.SecurityAndAnalysis.PushProtection.Status = "disabled" }},
		{name: "security fixes disabled", kind: "dependabot-security-updates", mutate: func(github *fakeGitHub) { github.fixes.Enabled = false }},
		{name: "security fixes paused", kind: "dependabot-security-updates", mutate: func(github *fakeGitHub) { github.fixes.Paused = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			github, client, manifest := convergedFakeGitHub(t)
			github.mu.Lock()
			test.mutate(github)
			github.mu.Unlock()
			plan, err := BuildPlan(context.Background(), client, manifest)
			if err != nil {
				t.Fatalf("BuildPlan() error = %v", err)
			}
			if len(plan.Operations) != 1 || plan.Operations[0].Kind != test.kind {
				t.Fatalf("Operations = %#v, want only %q", plan.Operations, test.kind)
			}
		})
	}
}

func TestRepositorySettingsDriftDetectsEveryIndependentField(t *testing.T) {
	desired := repositoryState{
		AllowSquashMerge:         true,
		DeleteBranchOnMerge:      true,
		AllowUpdateBranch:        true,
		SquashMergeCommitTitle:   "COMMIT_OR_PR_TITLE",
		SquashMergeCommitMessage: "COMMIT_MESSAGES",
	}
	if repositorySettingsDrift(desired) {
		t.Fatal("repositorySettingsDrift(desired) = true")
	}
	tests := []struct {
		name   string
		mutate func(*repositoryState)
	}{
		{name: "squash merge", mutate: func(state *repositoryState) { state.AllowSquashMerge = false }},
		{name: "merge commit", mutate: func(state *repositoryState) { state.AllowMergeCommit = true }},
		{name: "rebase merge", mutate: func(state *repositoryState) { state.AllowRebaseMerge = true }},
		{name: "delete branch", mutate: func(state *repositoryState) { state.DeleteBranchOnMerge = false }},
		{name: "update branch", mutate: func(state *repositoryState) { state.AllowUpdateBranch = false }},
		{name: "squash title", mutate: func(state *repositoryState) { state.SquashMergeCommitTitle = "PR_TITLE" }},
		{name: "squash message", mutate: func(state *repositoryState) { state.SquashMergeCommitMessage = "PR_BODY" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := desired
			test.mutate(&state)
			if !repositorySettingsDrift(state) {
				t.Fatal("repositorySettingsDrift(drifted) = false")
			}
		})
	}
}

func TestOperationsEqualChecksEveryFieldAndCanonicalBody(t *testing.T) {
	base := operation("gomaja/example", "actions-policy", http.MethodPut, "/repos/gomaja/example/actions", json.RawMessage(`{"a":1,"b":2}`))
	equivalent := base
	equivalent.Body = json.RawMessage(" { \"a\": 1, \"b\": 2 } ")
	if !operationsEqual(base, equivalent) {
		t.Fatal("operationsEqual(canonical JSON) = false")
	}
	tests := []struct {
		name   string
		mutate func(*Operation)
	}{
		{name: "repository", mutate: func(operation *Operation) { operation.Repository = "gomaja/other" }},
		{name: "kind", mutate: func(operation *Operation) { operation.Kind = "selected-actions" }},
		{name: "method", mutate: func(operation *Operation) { operation.Method = http.MethodPatch }},
		{name: "path", mutate: func(operation *Operation) { operation.Path += "/other" }},
		{name: "body", mutate: func(operation *Operation) { operation.Body = json.RawMessage(`{"a":2}`) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			if operationsEqual(base, changed) {
				t.Fatal("operationsEqual(different operation) = true")
			}
		})
	}

	for _, test := range []struct {
		name        string
		left, right json.RawMessage
		want        bool
	}{
		{name: "both absent", want: true},
		{name: "left absent", right: json.RawMessage(`{}`)},
		{name: "right absent", left: json.RawMessage(`{}`)},
		{name: "same JSON", left: json.RawMessage(`{"a":1}`), right: json.RawMessage(" { \"a\": 1 } "), want: true},
		{name: "malformed JSON", left: json.RawMessage(`{`), right: json.RawMessage(`{`)},
	} {
		t.Run("body "+test.name, func(t *testing.T) {
			if got := equalJSONBody(test.left, test.right); got != test.want {
				t.Fatalf("equalJSONBody() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestListRulesetsVisitsAllOneHundredPages(t *testing.T) {
	var requests atomic.Int32
	fullPage := make([]rulesetSummary, 100)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		page := int(requests.Add(1))
		if request.URL.Query().Get("page") != strconv.Itoa(page) {
			http.Error(writer, `{"message":"unexpected page"}`, http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if page < 100 {
			writeFakeJSON(writer, fullPage)
			return
		}
		writeFakeJSON(writer, []rulesetSummary{})
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}

	rulesets, err := listRulesets(context.Background(), client, "/repos/gomaja/example")
	if err != nil {
		t.Fatalf("listRulesets() error = %v", err)
	}
	if requests.Load() != 100 || len(rulesets) != 9_900 {
		t.Fatalf("listRulesets() made %d requests and returned %d rulesets", requests.Load(), len(rulesets))
	}
}

func TestNormalizeRulesetCanonicalizesNilAndPreservesValues(t *testing.T) {
	nilPayload := rulesetPayload{}
	normalizeRuleset(&nilPayload)
	if nilPayload.BypassActors == nil || nilPayload.Conditions.RefName.Include == nil ||
		nilPayload.Conditions.RefName.Exclude == nil || nilPayload.Rules == nil {
		t.Fatalf("normalizeRuleset(nil fields) = %#v, want non-nil empty collections", nilPayload)
	}

	populated := rulesetPayload{
		BypassActors: []any{"actor"},
		Conditions: rulesetConditions{RefName: refCondition{
			Include: []string{"z", "a"},
			Exclude: []string{"excluded"},
		}},
		Rules: []rulesetRule{{Type: "z"}, {Type: "a"}},
	}
	normalizeRuleset(&populated)
	if len(populated.BypassActors) != 1 || populated.BypassActors[0] != "actor" ||
		!slices.Equal(populated.Conditions.RefName.Include, []string{"a", "z"}) ||
		!slices.Equal(populated.Conditions.RefName.Exclude, []string{"excluded"}) ||
		len(populated.Rules) != 2 || populated.Rules[0].Type != "a" || populated.Rules[1].Type != "z" {
		t.Fatalf("normalizeRuleset(populated) = %#v, want preserved and sorted values", populated)
	}
}

func TestSupportedMutationMethods(t *testing.T) {
	for _, method := range []string{http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodDelete} {
		if !supportedMutation(method) {
			t.Errorf("supportedMutation(%q) = false", method)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, ""} {
		if supportedMutation(method) {
			t.Errorf("supportedMutation(%q) = true", method)
		}
	}
}

func TestCompareRulesetSummaryOrdersEveryRelationship(t *testing.T) {
	low := rulesetSummary{ID: 1}
	high := rulesetSummary{ID: 2}
	if got := compareRulesetSummary(low, high); got != -1 {
		t.Fatalf("compareRulesetSummary(low, high) = %d", got)
	}
	if got := compareRulesetSummary(high, low); got != 1 {
		t.Fatalf("compareRulesetSummary(high, low) = %d", got)
	}
	if got := compareRulesetSummary(low, low); got != 0 {
		t.Fatalf("compareRulesetSummary(equal) = %d", got)
	}
}

func convergeFakeGitHub(t *testing.T, client Client, manifest config.Governance) {
	t.Helper()
	plan, err := BuildPlan(context.Background(), client, manifest)
	if err != nil {
		t.Fatalf("BuildPlan() error = %v", err)
	}
	if err := Apply(context.Background(), client, manifest, plan, plan.ID); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
}

func convergedFakeGitHub(t *testing.T) (*fakeGitHub, Client, config.Governance) {
	t.Helper()
	github := newFakeGitHub()
	server := httptest.NewServer(github)
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
	manifest := testGovernance()
	convergeFakeGitHub(t, client, manifest)
	return github, client, manifest
}

func validEmptyPlan(apiVersion string) Plan {
	plan := Plan{SchemaVersion: "1", APIVersion: apiVersion, ObservedHash: strings.Repeat("a", 64), Operations: []Operation{}}
	plan.ID = planDigest(plan)
	return plan
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
