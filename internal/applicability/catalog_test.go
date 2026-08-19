package applicability

import (
	"slices"
	"testing"

	"github.com/gomaja/github-ci/internal/config"
)

func TestDefaultCatalogIsValidAndComplete(t *testing.T) {
	catalog := DefaultCatalog()
	if err := catalog.Validate(); err != nil {
		t.Fatalf("DefaultCatalog().Validate() error = %v", err)
	}

	wantTools := []string{
		"actionlint", "apidiff", "bash", "checkov", "codeql", "dependency-review", "generated", "gitleaks",
		"go", "gofmt", "goimports", "golangci-lint", "gopls",
		"govulncheck", "grype", "hadolint", "json", "license", "markdownlint", "osv-scanner",
		"repository", "scorecard", "semgrep", "shellcheck", "shfmt", "staticcheck", "syft", "trivy", "yamllint", "zizmor",
	}
	for _, tool := range wantTools {
		if !catalog.HasTool(tool) {
			t.Errorf("DefaultCatalog() missing tool %q", tool)
		}
	}
	for _, entry := range catalog {
		if entry.Tool == "scorecard" && entry.ParserVersion != "scorecard-sarif/v1" {
			t.Errorf("Scorecard parser = %q, want scorecard-sarif/v1", entry.ParserVersion)
		}
	}

	wantIdentities := []string{
		"actionlint/actionlint/workflows",
		"apidiff/apidiff/public-api",
		"bash/bash/scripts",
		"checkov/checkov/infrastructure",
		"codeql/codeql/actions",
		"codeql/codeql/go",
		"dependency-review/dependency-review/changes",
		"generated/generated/files",
		"gitleaks/gitleaks/content",
		"go/go/build",
		"go/go/module-integrity",
		"go/go/race",
		"go/go/test",
		"go/go/vet",
		"gofmt/gofmt/tracked-go",
		"goimports/goimports/tracked-go",
		"golangci-lint/golangci-lint/default",
		"gopls/gopls/tracked-go",
		"govulncheck/govulncheck/modules",
		"grype/grype/sbom",
		"hadolint/hadolint/dockerfiles",
		"json/json/documents",
		"license/license/dependencies",
		"markdownlint/markdownlint/documents",
		"osv-scanner/osv-scanner/dependencies",
		"repository/repository/hygiene",
		"scorecard/scorecard/repository",
		"semgrep/semgrep/source",
		"shellcheck/shellcheck/scripts",
		"shfmt/shfmt/scripts",
		"staticcheck/staticcheck/default",
		"syft/syft/sbom",
		"trivy/trivy/filesystem",
		"yamllint/yamllint/documents",
		"zizmor/zizmor/workflows",
	}
	gotIdentities := make([]string, 0, len(catalog))
	for _, entry := range catalog {
		gotIdentities = append(gotIdentities, entry.Tool+"/"+entry.CommandID)
	}
	slices.Sort(gotIdentities)
	if !slices.Equal(gotIdentities, wantIdentities) {
		t.Fatalf("DefaultCatalog() identities = %#v, want %#v", gotIdentities, wantIdentities)
	}
}

func TestCatalogRejectsInvalidEntries(t *testing.T) {
	base := DefaultCatalog()[0]
	tests := []struct {
		name   string
		mutate func(*Catalog)
	}{
		{name: "empty", mutate: func(catalog *Catalog) { *catalog = nil }},
		{name: "duplicate", mutate: func(catalog *Catalog) { *catalog = append(*catalog, base) }},
		{name: "invalid tool", mutate: func(catalog *Catalog) { (*catalog)[0].Tool = "Bad Tool" }},
		{name: "invalid command", mutate: func(catalog *Catalog) { (*catalog)[0].CommandID = "../bad" }},
		{name: "missing parser", mutate: func(catalog *Catalog) { (*catalog)[0].ParserVersion = "" }},
		{name: "invalid capability", mutate: func(catalog *Catalog) { (*catalog)[0].Capability = "unknown" }},
		{name: "missing reason", mutate: func(catalog *Catalog) { (*catalog)[0].ReasonCode = "" }},
		{name: "always reason", mutate: func(catalog *Catalog) {
			(*catalog)[0].Capability = CapabilityAlways
			(*catalog)[0].ReasonCode = ReasonNoGoModule
		}},
		{name: "empty profiles", mutate: func(catalog *Catalog) { (*catalog)[0].Profiles = nil }},
		{name: "duplicate profile", mutate: func(catalog *Catalog) {
			(*catalog)[0].Profiles = []config.Profile{config.ProfileGoStrict, config.ProfileGoStrict}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := DefaultCatalog()
			test.mutate(&catalog)
			if err := catalog.Validate(); err == nil {
				t.Fatal("Catalog.Validate() error = nil")
			}
		})
	}
}

func TestKnownReasonCodesAndToolsComeFromCatalog(t *testing.T) {
	if !IsReasonCode(ReasonNoDockerfiles) {
		t.Fatalf("IsReasonCode(%q) = false", ReasonNoDockerfiles)
	}
	if IsReasonCode("missing-tool") {
		t.Fatal("IsReasonCode(missing-tool) = true")
	}
	if !IsKnownTool("staticcheck") {
		t.Fatal("IsKnownTool(staticcheck) = false")
	}
	if IsKnownTool("unknown-scanner") {
		t.Fatal("IsKnownTool(unknown-scanner) = true")
	}
}

func TestReasonForBindsReasonToCommand(t *testing.T) {
	if got, ok := ReasonFor("staticcheck", "staticcheck/default"); !ok || got != ReasonNoGoModule {
		t.Fatalf("ReasonFor(staticcheck) = %q, %t", got, ok)
	}
	if got, ok := ReasonFor("staticcheck", "hadolint/dockerfiles"); ok || got != "" {
		t.Fatalf("ReasonFor(mismatched command) = %q, %t", got, ok)
	}
}
