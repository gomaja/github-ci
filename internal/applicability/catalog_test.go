package applicability

import (
	"testing"

	"github.com/gomaja/github-ci/internal/config"
)

func TestDefaultCatalogIsValidAndComplete(t *testing.T) {
	catalog := DefaultCatalog()
	if err := catalog.Validate(); err != nil {
		t.Fatalf("DefaultCatalog().Validate() error = %v", err)
	}

	wantTools := []string{
		"actionlint", "checkov", "codeql", "dependency-review", "gitleaks",
		"go", "gofmt", "goimports", "golangci-lint", "gopls",
		"govulncheck", "hadolint", "markdownlint", "osv-scanner",
		"semgrep", "shellcheck", "shfmt", "staticcheck", "trivy", "yamllint", "zizmor",
	}
	for _, tool := range wantTools {
		if !catalog.HasTool(tool) {
			t.Errorf("DefaultCatalog() missing tool %q", tool)
		}
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
