package governance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gomaja/github-ci/internal/config"
)

const securityEnabled = "enabled"

// Plan is an ordered, content-addressed desired-state change set.
type Plan struct {
	SchemaVersion string      `json:"schema_version"`
	APIVersion    string      `json:"api_version"`
	ObservedHash  string      `json:"observed_hash"`
	ID            string      `json:"id"`
	Operations    []Operation `json:"operations"`
}

// Operation is one exact GitHub REST mutation.
type Operation struct {
	Repository string          `json:"repository"`
	Kind       string          `json:"kind"`
	Method     string          `json:"method"`
	Path       string          `json:"path"`
	Body       json.RawMessage `json:"body,omitempty"`
}

type repositoryState struct {
	Name                     string `json:"name"`
	Private                  bool   `json:"private"`
	Fork                     bool   `json:"fork"`
	Archived                 bool   `json:"archived"`
	DefaultBranch            string `json:"default_branch"`
	AllowSquashMerge         bool   `json:"allow_squash_merge"`
	AllowMergeCommit         bool   `json:"allow_merge_commit"`
	AllowRebaseMerge         bool   `json:"allow_rebase_merge"`
	DeleteBranchOnMerge      bool   `json:"delete_branch_on_merge"`
	AllowUpdateBranch        bool   `json:"allow_update_branch"`
	SquashMergeCommitTitle   string `json:"squash_merge_commit_title"`
	SquashMergeCommitMessage string `json:"squash_merge_commit_message"`
	Owner                    struct {
		Login string `json:"login"`
	} `json:"owner"`
	SecurityAndAnalysis struct {
		SecretScanning struct {
			Status string `json:"status"`
		} `json:"secret_scanning"`
		PushProtection struct {
			Status string `json:"status"`
		} `json:"secret_scanning_push_protection"`
	} `json:"security_and_analysis"`
}

type actionsState struct {
	Enabled            bool   `json:"enabled"`
	AllowedActions     string `json:"allowed_actions"`
	SHAPinningRequired bool   `json:"sha_pinning_required"`
}

type workflowState struct {
	DefaultPermissions string `json:"default_workflow_permissions"`
	CanApprove         bool   `json:"can_approve_pull_request_reviews"`
}

type selectedActionsState struct {
	GitHubOwnedAllowed bool     `json:"github_owned_allowed"`
	VerifiedAllowed    bool     `json:"verified_allowed"`
	PatternsAllowed    []string `json:"patterns_allowed"`
}

type enabledState struct {
	Enabled bool `json:"enabled"`
	Paused  bool `json:"paused,omitempty"`
}

type rulesetSummary struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Target string `json:"target"`
}

type rulesetPayload struct {
	Name         string            `json:"name"`
	Target       string            `json:"target"`
	Enforcement  string            `json:"enforcement"`
	BypassActors []any             `json:"bypass_actors"`
	Conditions   rulesetConditions `json:"conditions"`
	Rules        []rulesetRule     `json:"rules"`
}

type rulesetConditions struct {
	RefName refCondition `json:"ref_name"`
}

type refCondition struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

type rulesetRule struct {
	Type       string         `json:"type"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

// BuildPlan reads live state and returns only required mutations.
func BuildPlan(ctx context.Context, client Client, manifest config.Governance) (Plan, error) {
	if err := manifest.Validate(); err != nil {
		return Plan{}, err
	}
	if client.APIVersion != manifest.APIVersion {
		return Plan{}, errors.New("client and governance API versions differ")
	}

	operations := make([]Operation, 0)
	observed := make([]json.RawMessage, 0)
	for _, repository := range manifest.Repositories {
		owner := repository.Owner
		if owner == "" {
			owner = manifest.Owners[0].Name
		}
		fullName := owner + "/" + repository.Name
		base := "/repos/" + fullName

		var state repositoryState
		if _, err := client.do(ctx, http.MethodGet, base, nil, &state); err != nil {
			return Plan{}, fmt.Errorf("read %s: %w", fullName, err)
		}
		observed = append(observed, mustJSON(state))
		if state.Private || state.Fork || state.Archived || state.Name != repository.Name ||
			!strings.EqualFold(state.Owner.Login, owner) || state.DefaultBranch != manifest.Defaults.DefaultBranch {
			return Plan{}, fmt.Errorf("repository %s violates immutable governance scope", fullName)
		}
		if repositorySettingsDrift(state) {
			body := mustJSON(map[string]any{
				"allow_squash_merge": true, "allow_merge_commit": false, "allow_rebase_merge": false,
				"delete_branch_on_merge": true, "allow_update_branch": true,
				"squash_merge_commit_title": "COMMIT_OR_PR_TITLE", "squash_merge_commit_message": "COMMIT_MESSAGES",
			})
			operations = append(operations, operation(fullName, "repository-settings", http.MethodPatch, base, body))
		}

		var err error
		operations, observed, err = appendActionsOperations(ctx, client, operations, observed, fullName, base)
		if err != nil {
			return Plan{}, err
		}
		operations, observed, err = appendSecurityOperations(ctx, client, operations, observed, fullName, base, state)
		if err != nil {
			return Plan{}, err
		}
		operations, observed, err = appendRulesetOperations(ctx, client, operations, observed, fullName, base, repository)
		if err != nil {
			return Plan{}, err
		}
	}

	slices.SortFunc(operations, compareOperations)
	plan := Plan{
		SchemaVersion: "1",
		APIVersion:    manifest.APIVersion,
		ObservedHash:  digestJSON(observed),
		Operations:    operations,
	}
	plan.ID = planDigest(plan)
	return plan, nil
}

// Apply revalidates all remaining operations before each exact mutation.
func Apply(ctx context.Context, client Client, manifest config.Governance, plan Plan, confirm string) error {
	identity := plan
	identity.ID = ""
	if plan.SchemaVersion != "1" || plan.ID == "" || plan.ID != planDigest(identity) {
		return errors.New("invalid governance plan identity")
	}
	if confirm != plan.ID {
		return errors.New("confirmation does not match governance plan id")
	}
	if client.APIVersion != plan.APIVersion || manifest.APIVersion != plan.APIVersion {
		return errors.New("client, manifest, and plan API versions differ")
	}

	remaining := slices.Clone(plan.Operations)
	for len(remaining) != 0 {
		live, err := BuildPlan(ctx, client, manifest)
		if err != nil {
			return fmt.Errorf("revalidate governance plan: %w", err)
		}
		if !slices.EqualFunc(live.Operations, remaining, operationsEqual) {
			return fmt.Errorf("live repository state no longer matches the approved governance plan: live %s, approved %s", operationSummary(live.Operations), operationSummary(remaining))
		}
		current := remaining[0]
		if !supportedMutation(current.Method) {
			return fmt.Errorf("operation %s has unsupported method", current.Kind)
		}
		if _, err := client.do(ctx, current.Method, current.Path, current.Body, nil); err != nil {
			return fmt.Errorf("apply %s to %s: %w", current.Kind, current.Repository, err)
		}
		remaining = remaining[1:]
	}

	live, err := BuildPlan(ctx, client, manifest)
	if err != nil {
		return fmt.Errorf("verify governance convergence: %w", err)
	}
	if len(live.Operations) != 0 {
		return errors.New("governance apply did not converge")
	}
	return nil
}

func appendActionsOperations(ctx context.Context, client Client, operations []Operation, observed []json.RawMessage, fullName, base string) ([]Operation, []json.RawMessage, error) {
	var actions actionsState
	if _, err := client.do(ctx, http.MethodGet, base+"/actions/permissions", nil, &actions); err != nil {
		return nil, nil, fmt.Errorf("read %s Actions policy: %w", fullName, err)
	}
	observed = append(observed, mustJSON(actions))
	desiredActions := actionsState{Enabled: true, AllowedActions: "selected", SHAPinningRequired: true}
	if actions != desiredActions {
		operations = append(operations, operation(fullName, "actions-policy", http.MethodPut, base+"/actions/permissions", mustJSON(desiredActions)))
	}

	var workflow workflowState
	if _, err := client.do(ctx, http.MethodGet, base+"/actions/permissions/workflow", nil, &workflow); err != nil {
		return nil, nil, fmt.Errorf("read %s workflow permissions: %w", fullName, err)
	}
	observed = append(observed, mustJSON(workflow))
	if workflow.DefaultPermissions != "read" || workflow.CanApprove {
		body := mustJSON(map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
		operations = append(operations, operation(fullName, "workflow-permissions", http.MethodPut, base+"/actions/permissions/workflow", body))
	}

	desiredSelected := selectedActionsState{
		GitHubOwnedAllowed: true,
		VerifiedAllowed:    false,
		PatternsAllowed:    []string{"ossf/scorecard-action@*", "step-security/harden-runner@*"},
	}
	if actions.AllowedActions == "selected" {
		var selected selectedActionsState
		if _, err := client.do(ctx, http.MethodGet, base+"/actions/permissions/selected-actions", nil, &selected); err != nil {
			return nil, nil, fmt.Errorf("read %s selected Actions policy: %w", fullName, err)
		}
		normalizeSelectedActions(&selected)
		observed = append(observed, mustJSON(selected))
		if selected.GitHubOwnedAllowed != desiredSelected.GitHubOwnedAllowed ||
			selected.VerifiedAllowed != desiredSelected.VerifiedAllowed ||
			!slices.Equal(selected.PatternsAllowed, desiredSelected.PatternsAllowed) {
			operations = append(operations, operation(fullName, "selected-actions", http.MethodPut, base+"/actions/permissions/selected-actions", mustJSON(desiredSelected)))
		}
	} else {
		observed = append(observed, mustJSON(map[string]string{"selected_actions": "not-readable"}))
		operations = append(operations, operation(fullName, "selected-actions", http.MethodPut, base+"/actions/permissions/selected-actions", mustJSON(desiredSelected)))
	}
	return operations, observed, nil
}

func appendSecurityOperations(ctx context.Context, client Client, operations []Operation, observed []json.RawMessage, fullName, base string, state repositoryState) ([]Operation, []json.RawMessage, error) {
	if state.SecurityAndAnalysis.SecretScanning.Status != securityEnabled || state.SecurityAndAnalysis.PushProtection.Status != securityEnabled {
		body := mustJSON(map[string]any{"security_and_analysis": map[string]any{
			"secret_scanning":                 map[string]string{"status": securityEnabled},
			"secret_scanning_push_protection": map[string]string{"status": securityEnabled},
		}})
		operations = append(operations, operation(fullName, "secret-scanning", http.MethodPatch, base, body))
	}

	status, err := client.do(ctx, http.MethodGet, base+"/vulnerability-alerts", nil, nil)
	if err != nil && status != http.StatusNotFound {
		return nil, nil, fmt.Errorf("read %s Dependabot alerts: %w", fullName, err)
	}
	observed = append(observed, mustJSON(map[string]int{"dependabot_alerts_status": status}))
	if status == http.StatusNotFound {
		operations = append(operations, operation(fullName, "dependabot-alerts", http.MethodPut, base+"/vulnerability-alerts", nil))
	}

	var fixes enabledState
	if _, err := client.do(ctx, http.MethodGet, base+"/automated-security-fixes", nil, &fixes); err != nil {
		return nil, nil, fmt.Errorf("read %s Dependabot security updates: %w", fullName, err)
	}
	observed = append(observed, mustJSON(fixes))
	if !fixes.Enabled || fixes.Paused {
		operations = append(operations, operation(fullName, "dependabot-security-updates", http.MethodPut, base+"/automated-security-fixes", nil))
	}

	var reporting enabledState
	if _, err := client.do(ctx, http.MethodGet, base+"/private-vulnerability-reporting", nil, &reporting); err != nil {
		return nil, nil, fmt.Errorf("read %s private vulnerability reporting: %w", fullName, err)
	}
	observed = append(observed, mustJSON(reporting))
	if !reporting.Enabled {
		operations = append(operations, operation(fullName, "private-vulnerability-reporting", http.MethodPut, base+"/private-vulnerability-reporting", nil))
	}
	return operations, observed, nil
}

func appendRulesetOperations(ctx context.Context, client Client, operations []Operation, observed []json.RawMessage, fullName, base string, repository config.Repository) ([]Operation, []json.RawMessage, error) {
	summaries, err := listRulesets(ctx, client, base)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s rulesets: %w", fullName, err)
	}
	slices.SortFunc(summaries, func(left, right rulesetSummary) int {
		switch {
		case left.ID < right.ID:
			return -1
		case left.ID > right.ID:
			return 1
		default:
			return 0
		}
	})
	actual := make(map[int64]rulesetPayload, len(summaries))
	for _, summary := range summaries {
		var payload rulesetPayload
		path := fmt.Sprintf("%s/rulesets/%d", base, summary.ID)
		if _, err := client.do(ctx, http.MethodGet, path, nil, &payload); err != nil {
			return nil, nil, fmt.Errorf("read %s ruleset %d: %w", fullName, summary.ID, err)
		}
		normalizeRuleset(&payload)
		actual[summary.ID] = payload
		observed = append(observed, mustJSON(struct {
			ID      int64          `json:"id"`
			Payload rulesetPayload `json:"payload"`
		}{ID: summary.ID, Payload: payload}))
	}

	for _, desired := range []rulesetPayload{branchRuleset(repository), tagRuleset()} {
		normalizeRuleset(&desired)
		matches := make([]rulesetSummary, 0)
		for _, summary := range summaries {
			payload := actual[summary.ID]
			if payload.Name == desired.Name || sameRulesetScope(payload, desired) {
				matches = append(matches, summary)
			}
		}
		if len(matches) == 0 {
			operations = append(operations, operation(fullName, "create-ruleset", http.MethodPost, base+"/rulesets", mustJSON(desired)))
			continue
		}

		primary := matches[0]
		for _, candidate := range matches {
			if actual[candidate.ID].Name == desired.Name {
				primary = candidate
				break
			}
		}
		path := fmt.Sprintf("%s/rulesets/%d", base, primary.ID)
		if !rulesetsEqual(actual[primary.ID], desired) {
			operations = append(operations, operation(fullName, "update-ruleset", http.MethodPut, path, mustJSON(desired)))
		}
		for _, duplicate := range matches {
			if duplicate.ID != primary.ID {
				path := fmt.Sprintf("%s/rulesets/%d", base, duplicate.ID)
				operations = append(operations, operation(fullName, "delete-overlapping-ruleset", http.MethodDelete, path, nil))
			}
		}
	}
	return operations, observed, nil
}

func listRulesets(ctx context.Context, client Client, base string) ([]rulesetSummary, error) {
	const pageSize = 100
	all := make([]rulesetSummary, 0)
	for page := 1; page <= 100; page++ {
		var current []rulesetSummary
		path := fmt.Sprintf("%s/rulesets?per_page=%d&page=%d", base, pageSize, page)
		if _, err := client.do(ctx, http.MethodGet, path, nil, &current); err != nil {
			return nil, err
		}
		all = append(all, current...)
		if len(current) < pageSize {
			return all, nil
		}
	}
	return nil, errors.New("ruleset pagination exceeds 100 pages")
}

func branchRuleset(repository config.Repository) rulesetPayload {
	rules := []rulesetRule{
		{Type: "deletion"},
		{Type: "non_fast_forward"},
		{Type: "required_linear_history"},
		{Type: "creation"},
		{Type: "pull_request", Parameters: map[string]any{
			"required_approving_review_count":   0,
			"dismiss_stale_reviews_on_push":     true,
			"required_reviewers":                []any{},
			"require_code_owner_review":         true,
			"require_last_push_approval":        false,
			"required_review_thread_resolution": true,
			"allowed_merge_methods":             []string{"squash"},
		}},
		{Type: "copilot_code_review", Parameters: map[string]any{"review_on_push": true, "review_draft_pull_requests": false}},
		{Type: "code_scanning", Parameters: map[string]any{"code_scanning_tools": []map[string]string{{
			"tool": "CodeQL", "alerts_threshold": "all", "security_alerts_threshold": "all",
		}}}},
	}
	if repository.ObservedRequiredCheck != "" {
		rules = append(rules, rulesetRule{Type: "required_status_checks", Parameters: map[string]any{
			"strict_required_status_checks_policy": true,
			"do_not_enforce_on_create":             false,
			"required_status_checks":               []map[string]string{{"context": repository.ObservedRequiredCheck}},
		}})
	}
	return rulesetPayload{
		Name:         "github-ci default branch",
		Target:       "branch",
		Enforcement:  "active",
		BypassActors: []any{},
		Conditions:   rulesetConditions{RefName: refCondition{Include: []string{"~DEFAULT_BRANCH"}, Exclude: []string{}}},
		Rules:        rules,
	}
}

func tagRuleset() rulesetPayload {
	return rulesetPayload{
		Name:         "github-ci version tags",
		Target:       "tag",
		Enforcement:  "active",
		BypassActors: []any{},
		Conditions:   rulesetConditions{RefName: refCondition{Include: []string{"refs/tags/v*"}, Exclude: []string{}}},
		Rules:        []rulesetRule{{Type: "deletion"}, {Type: "non_fast_forward"}},
	}
}

func repositorySettingsDrift(state repositoryState) bool {
	return !state.AllowSquashMerge || state.AllowMergeCommit || state.AllowRebaseMerge ||
		!state.DeleteBranchOnMerge || !state.AllowUpdateBranch ||
		state.SquashMergeCommitTitle != "COMMIT_OR_PR_TITLE" || state.SquashMergeCommitMessage != "COMMIT_MESSAGES"
}

func normalizeSelectedActions(selected *selectedActionsState) {
	if selected.PatternsAllowed == nil {
		selected.PatternsAllowed = []string{}
	}
	slices.Sort(selected.PatternsAllowed)
}

func normalizeRuleset(payload *rulesetPayload) {
	if payload.BypassActors == nil {
		payload.BypassActors = []any{}
	}
	if payload.Conditions.RefName.Include == nil {
		payload.Conditions.RefName.Include = []string{}
	}
	if payload.Conditions.RefName.Exclude == nil {
		payload.Conditions.RefName.Exclude = []string{}
	}
	if payload.Rules == nil {
		payload.Rules = []rulesetRule{}
	}
	slices.Sort(payload.Conditions.RefName.Include)
	slices.Sort(payload.Conditions.RefName.Exclude)
	slices.SortFunc(payload.Rules, func(left, right rulesetRule) int { return strings.Compare(left.Type, right.Type) })
}

func sameRulesetScope(left, right rulesetPayload) bool {
	return left.Target == right.Target &&
		string(mustJSON(left.Conditions)) == string(mustJSON(right.Conditions))
}

func rulesetsEqual(left, right rulesetPayload) bool {
	normalizeRuleset(&left)
	normalizeRuleset(&right)
	return string(mustJSON(left)) == string(mustJSON(right))
}

func compareOperations(left, right Operation) int {
	if comparison := strings.Compare(left.Repository, right.Repository); comparison != 0 {
		return comparison
	}
	leftPriority := operationPriority(left.Kind)
	rightPriority := operationPriority(right.Kind)
	if leftPriority != rightPriority {
		return leftPriority - rightPriority
	}
	return strings.Compare(left.Kind+"\x00"+left.Path, right.Kind+"\x00"+right.Path)
}

func operationPriority(kind string) int {
	switch kind {
	case "repository-settings", "secret-scanning", "dependabot-alerts", "dependabot-security-updates", "private-vulnerability-reporting", "workflow-permissions":
		return 10
	case "actions-policy":
		return 20
	case "selected-actions":
		return 30
	case "create-ruleset", "update-ruleset":
		return 40
	case "delete-overlapping-ruleset":
		return 50
	default:
		return 100
	}
}

func supportedMutation(method string) bool {
	return method == http.MethodPatch || method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete
}

func operationsEqual(left, right Operation) bool {
	return left.Repository == right.Repository && left.Kind == right.Kind && left.Method == right.Method &&
		left.Path == right.Path && string(left.Body) == string(right.Body)
}

func operationSummary(operations []Operation) string {
	values := make([]string, len(operations))
	for index, operation := range operations {
		values[index] = operation.Repository + ":" + operation.Kind + ":" + operation.Path
	}
	return strings.Join(values, ",")
}

func operation(repository, kind, method, path string, body json.RawMessage) Operation {
	return Operation{Repository: repository, Kind: kind, Method: method, Path: path, Body: body}
}

func mustJSON(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func digestJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func planDigest(plan Plan) string {
	plan.ID = ""
	return digestJSON(plan)
}
