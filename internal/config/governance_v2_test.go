package config

import (
	"strings"
	"testing"
)

const validGovernanceV2 = `schema-version: 2
api-version: "2026-03-10"
owners:
  - name: gomaja
    type: user
defaults:
  profile: go-strict
  default-branch: main
  required-checks:
    - github-ci / gate
    - generated / verify
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

func TestDecodeGovernanceV2RequiredChecks(t *testing.T) {
	governance, err := DecodeGovernance(strings.NewReader(validGovernanceV2))
	if err != nil {
		t.Fatalf("DecodeGovernance() error = %v", err)
	}
	if got := strings.Join(governance.Defaults.RequiredChecks, ","); got != "github-ci / gate,generated / verify" {
		t.Fatalf("RequiredChecks = %q", got)
	}
}

func TestDecodeGovernanceV2RejectsInvalidRequiredChecks(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "schema 1", yaml: strings.Replace(validGovernanceV2, "schema-version: 2", "schema-version: 1", 1), want: "schema-version must be 2"},
		{name: "removed singular field", yaml: strings.Replace(validGovernanceV2, "required-checks:\n    - github-ci / gate\n    - generated / verify", "required-check: github-ci / gate", 1), want: "field required-check not found"},
		{name: "empty", yaml: strings.Replace(validGovernanceV2, "    - github-ci / gate\n    - generated / verify", "    []", 1), want: "at least one required check"},
		{name: "duplicate", yaml: strings.Replace(validGovernanceV2, "    - generated / verify", "    - github-ci / gate", 1), want: "duplicate required check"},
		{name: "blank", yaml: strings.Replace(validGovernanceV2, "    - generated / verify", "    - ''", 1), want: "required check must not be empty"},
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
