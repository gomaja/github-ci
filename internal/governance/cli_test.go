package governance

import (
	"strings"
	"testing"

	"github.com/gomaja/github-ci/internal/config"
)

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
