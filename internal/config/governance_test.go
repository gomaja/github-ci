package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestDecodeGovernance(t *testing.T) {
	valid, err := os.Open("../../testdata/config/governance-valid.yaml")
	if err != nil {
		t.Fatalf("open valid fixture: %v", err)
	}
	t.Cleanup(func() { _ = valid.Close() })

	governance, err := DecodeGovernance(valid)
	if err != nil {
		t.Fatalf("DecodeGovernance() error = %v", err)
	}
	if governance.APIVersion != "2026-03-10" {
		t.Fatalf("APIVersion = %q, want 2026-03-10", governance.APIVersion)
	}
	if len(governance.Repositories) != 2 {
		t.Fatalf("Repositories = %v, want two repositories", governance.Repositories)
	}
}

func TestDecodeGovernanceRejectsInvalidInput(t *testing.T) {
	valid := `schema-version: 1
api-version: "2026-03-10"
owners:
  - name: gomaja
    type: user
defaults:
  profile: go-strict
  default-branch: main
  required-check: github-ci / gate
  public-only: true
  refuse-forks: true
  refuse-archived: true
  refuse-private: true
  refuse-unexpected-owners: true
repositories:
  - name: github-ci
    owner: gomaja
    enforce-caller: false
`

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "unknown field", yaml: valid + "unknown: true\n", want: "field unknown not found"},
		{name: "invalid owner type", yaml: strings.Replace(valid, "type: user", "type: team", 1), want: "unsupported owner type"},
		{name: "invalid owner name", yaml: strings.Replace(valid, "name: gomaja", "name: ../gomaja", 1), want: "invalid GitHub owner name"},
		{name: "non-public defaults", yaml: strings.Replace(valid, "public-only: true", "public-only: false", 1), want: "public-only"},
		{name: "forks permitted", yaml: strings.Replace(valid, "refuse-forks: true", "refuse-forks: false", 1), want: "refuse-forks"},
		{name: "archived permitted", yaml: strings.Replace(valid, "refuse-archived: true", "refuse-archived: false", 1), want: "refuse-archived"},
		{name: "private permitted", yaml: strings.Replace(valid, "refuse-private: true", "refuse-private: false", 1), want: "refuse-private"},
		{name: "unexpected owners permitted", yaml: strings.Replace(valid, "refuse-unexpected-owners: true", "refuse-unexpected-owners: false", 1), want: "refuse-unexpected-owners"},
		{name: "duplicate repository", yaml: valid + "  - name: github-ci\n    owner: gomaja\n    enforce-caller: false\n", want: "duplicate repository"},
		{name: "unknown repository owner", yaml: strings.Replace(valid, "owner: gomaja", "owner: elsewhere", 1), want: "unexpected owner"},
		{name: "invalid repository name", yaml: strings.Replace(valid, "name: github-ci", "name: ../github-ci", 1), want: "invalid GitHub repository name"},
		{name: "api version", yaml: strings.Replace(valid, "2026-03-10", "2025-01-01", 1), want: "api-version"},
		{name: "enforced caller without sha", yaml: strings.Replace(valid, "enforce-caller: false", "enforce-caller: true", 1), want: "workflow-sha"},
		{name: "enforced caller without required check", yaml: strings.Replace(valid, "enforce-caller: false", "enforce-caller: true\n    workflow-sha: 0123456789abcdef0123456789abcdef01234567", 1), want: "observed-required-check"},
		{name: "invalid workflow sha", yaml: strings.Replace(valid, "enforce-caller: false", "enforce-caller: true\n    workflow-sha: main\n    observed-required-check: github-ci / gate", 1), want: "immutable 40-character"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeGovernance(strings.NewReader(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("DecodeGovernance() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestGovernanceSchemaIsValidJSON(t *testing.T) {
	data, err := os.ReadFile("../../schemas/governance.schema.json")
	if err != nil {
		t.Fatalf("read governance schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("unmarshal governance schema: %v", err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema = %v", schema["$schema"])
	}
}
