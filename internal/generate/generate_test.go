package generate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLoadPolicyRejectsIncompleteAndDuplicateLocks(t *testing.T) {
	valid := `schema-version: 1
go-versions:
  current: 1.26.6
  previous: 1.25.13
actions:
  - id: checkout
    repository: actions/checkout
    release: v7.0.1
    sha: 3d3c42e5aac5ba805825da76410c181273ba90b1
tools:
  - id: staticcheck
    version: "2026.1"
    source: https://github.com/dominikh/go-tools
    checksum: h1:w6WUp1VbkqPEgLz4rkBzH/CSU6HkoqNLp6GstyTx3lU=
    parser: staticcheck-jsonl/v1
    profiles: [go-strict, go-library]
    acquisition: go-module
    version-command: staticcheck -version
`
	if _, err := LoadPolicy(strings.NewReader(valid)); err != nil {
		t.Fatalf("LoadPolicy(valid) error = %v", err)
	}

	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "symbolic action", body: strings.Replace(valid, "3d3c42e5aac5ba805825da76410c181273ba90b1", "v7", 1), want: "40-character"},
		{name: "missing checksum", body: strings.Replace(valid, "    checksum: h1:w6WUp1VbkqPEgLz4rkBzH/CSU6HkoqNLp6GstyTx3lU=\n", "", 1), want: "checksum"},
		{name: "missing version command", body: strings.Replace(valid, "    version-command: staticcheck -version\n", "", 1), want: "version-command"},
		{name: "duplicate tool", body: valid + strings.Split(valid, "tools:\n")[1], want: "duplicate tool id"},
		{name: "unknown field", body: valid + "unknown: true\n", want: "field unknown not found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadPolicy(strings.NewReader(test.body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadPolicy() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDecodeStrictRejectsMultipleDocumentsExactly(t *testing.T) {
	var destination map[string]any
	err := decodeStrict(strings.NewReader("value: one\n---\nvalue: two\n"), &destination)
	if err == nil || err.Error() != "YAML contains multiple documents" {
		t.Fatalf("decodeStrict() error = %v", err)
	}
}

func TestLoadPolicyAcceptsActionEntrypointSubpaths(t *testing.T) {
	body := `schema-version: 1
go-versions:
  current: 1.26.6
  previous: 1.25.13
actions:
  - id: codeql-init
    repository: github/codeql-action/init
    release: v4.37.7
    sha: ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd
tools:
  - id: staticcheck
    version: "2026.1"
    source: https://github.com/dominikh/go-tools
    checksum: h1:w6WUp1VbkqPEgLz4rkBzH/CSU6HkoqNLp6GstyTx3lU=
    parser: staticcheck-jsonl/v1
    profiles: [go-strict]
    acquisition: go-module
    version-command: staticcheck -version
`
	if _, err := LoadPolicy(strings.NewReader(body)); err != nil {
		t.Fatalf("LoadPolicy(action subpath) error = %v", err)
	}
}

func TestLoadLintersRequiresExactly74UniqueEntries(t *testing.T) {
	var body strings.Builder
	body.WriteString("schema-version: 1\nlinters:\n")
	for index := range 74 {
		fmt.Fprintf(&body, "  - linter%02d\n", index)
	}
	if _, err := LoadLinters(strings.NewReader(body.String())); err != nil {
		t.Fatalf("LoadLinters(valid) error = %v", err)
	}
	if _, err := LoadLinters(strings.NewReader(strings.Replace(body.String(), "  - linter00\n", "  - linter01\n", 1))); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("LoadLinters(duplicate) error = %v", err)
	}
	if _, err := LoadLinters(strings.NewReader(strings.Replace(body.String(), "  - linter00\n", "", 1))); err == nil || !strings.Contains(err.Error(), "exactly 74") {
		t.Fatalf("LoadLinters(short) error = %v", err)
	}
}

func TestLoadPolicyRequiresDigestPinnedContainerImages(t *testing.T) {
	body := `schema-version: 1
go-versions:
  current: 1.26.6
  previous: 1.25.13
actions:
  - id: checkout
    repository: actions/checkout
    release: v7.0.1
    sha: 3d3c42e5aac5ba805825da76410c181273ba90b1
tools:
  - id: semgrep
    version: 1.173.0
    source: https://hub.docker.com/r/semgrep/semgrep
    checksum: sha256:67319956da3dcb58baf5b322899c15458e3963e7018a86aeeb5cd224e69cb77a
    parser: semgrep-json/v1
    profiles: [go-strict]
    acquisition: container-image
    image: docker.io/semgrep/semgrep@sha256:67319956da3dcb58baf5b322899c15458e3963e7018a86aeeb5cd224e69cb77a
    version-command: semgrep --version
`
	if _, err := LoadPolicy(strings.NewReader(body)); err != nil {
		t.Fatalf("LoadPolicy(container) error = %v", err)
	}
	for _, mutation := range []string{
		strings.Replace(body, "    image: docker.io/semgrep/semgrep@sha256:67319956da3dcb58baf5b322899c15458e3963e7018a86aeeb5cd224e69cb77a\n", "", 1),
		strings.Replace(body, "image: docker.io/semgrep/semgrep@sha256:67319956da3dcb58baf5b322899c15458e3963e7018a86aeeb5cd224e69cb77a", "image: docker.io/semgrep/semgrep:latest", 1),
		strings.Replace(body, "image: docker.io/semgrep/semgrep@sha256:67319956da3dcb58baf5b322899c15458e3963e7018a86aeeb5cd224e69cb77a", "image: docker.io/semgrep/semgrep@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1),
	} {
		if _, err := LoadPolicy(strings.NewReader(mutation)); err == nil {
			t.Fatal("LoadPolicy() accepted an invalid container lock")
		}
	}
}

func TestValidateRejectsDescendingLocks(t *testing.T) {
	validAction := func(id string) Action {
		return Action{
			ID:         id,
			Repository: "actions/checkout",
			Release:    "v7.0.1",
			SHA:        "3d3c42e5aac5ba805825da76410c181273ba90b1",
		}
	}
	if err := validateActions([]Action{validAction("beta"), validAction("alpha")}); err == nil || err.Error() != "actions must be sorted by id" {
		t.Fatalf("validateActions(descending) error = %v", err)
	}

	validTool := func(id string) Tool {
		return Tool{
			ID:             id,
			Version:        "1.0.0",
			Source:         "https://example.com/tool",
			Checksum:       "sha256:" + strings.Repeat("a", 64),
			Parser:         "json/v1",
			Profiles:       []string{"go-strict"},
			Acquisition:    "go-module",
			VersionCommand: "tool --version",
		}
	}
	if err := validateTools([]Tool{validTool("beta"), validTool("alpha")}); err == nil || err.Error() != "tools must be sorted by id" {
		t.Fatalf("validateTools(descending) error = %v", err)
	}

	var linters strings.Builder
	linters.WriteString("schema-version: 1\nlinters:\n")
	for index := range 74 {
		name := fmt.Sprintf("linter%02d", index)
		switch index {
		case 0:
			name = "linter01"
		case 1:
			name = "linter00"
		}
		fmt.Fprintf(&linters, "  - %s\n", name)
	}
	if _, err := LoadLinters(strings.NewReader(linters.String())); err == nil || err.Error() != "linters must be sorted by name" {
		t.Fatalf("LoadLinters(descending) error = %v", err)
	}
}

func TestValidateToolAcquisitionAcceptsOnlySupportedKinds(t *testing.T) {
	for _, acquisition := range []string{
		"go-module",
		"release-asset",
		"pypi-sdist",
		"npm-package",
		"go-toolchain",
	} {
		t.Run(acquisition, func(t *testing.T) {
			if err := validateToolAcquisition(Tool{ID: "tool", Acquisition: acquisition}); err != nil {
				t.Fatalf("validateToolAcquisition(%q) error = %v", acquisition, err)
			}
		})
	}

	checksum := "sha256:" + strings.Repeat("a", 64)
	container := Tool{
		ID:          "container",
		Acquisition: acquisitionContainerImage,
		Checksum:    checksum,
		Image:       "example.com/tool@" + checksum,
	}
	if err := validateToolAcquisition(container); err != nil {
		t.Fatalf("validateToolAcquisition(container-image) error = %v", err)
	}
	if err := validateToolAcquisition(Tool{ID: "tool", Acquisition: "source-build"}); err == nil || err.Error() != `tool "tool" has unsupported acquisition "source-build"` {
		t.Fatalf("validateToolAcquisition(unsupported) error = %v", err)
	}
}

func TestPolicyLookupsRequireExactKindAndID(t *testing.T) {
	policy := Policy{
		Actions: []Action{
			{ID: "checkout", Repository: "actions/checkout", SHA: strings.Repeat("a", 40)},
			{ID: "setup-go", Repository: "actions/setup-go", SHA: strings.Repeat("b", 40)},
		},
		Tools: []Tool{
			{ID: "staticcheck", Acquisition: "go-module"},
			{ID: "semgrep", Acquisition: acquisitionContainerImage, Image: "example.com/semgrep@sha256:" + strings.Repeat("c", 64)},
		},
	}

	action, err := policy.Action("checkout")
	if err != nil || action != "actions/checkout@"+strings.Repeat("a", 40) {
		t.Fatalf("Action(checkout) = %q, %v", action, err)
	}
	if _, err := policy.Action("missing"); err == nil || err.Error() != `action lock "missing" not found` {
		t.Fatalf("Action(missing) error = %v", err)
	}

	image, err := policy.ToolImage("semgrep")
	if err != nil || image != policy.Tools[1].Image {
		t.Fatalf("ToolImage(semgrep) = %q, %v", image, err)
	}
	if _, err := policy.ToolImage("staticcheck"); err == nil || err.Error() != `container tool lock "staticcheck" not found` {
		t.Fatalf("ToolImage(staticcheck) error = %v", err)
	}
}

func TestCheckedInPolicyBindsSemanticParsers(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "policies", "tools.yaml"))
	if err != nil {
		t.Fatalf("open checked-in policy: %v", err)
	}
	policy, loadErr := LoadPolicy(file)
	closeErr := file.Close()
	if loadErr != nil || closeErr != nil {
		t.Fatalf("load checked-in policy: %v, close: %v", loadErr, closeErr)
	}

	want := map[string]string{
		"go-current":  "command-status/v1",
		"go-previous": "command-status/v1",
		"gopls":       "gopls-diagnostics/v1",
	}
	for _, tool := range policy.Tools {
		parser, exists := want[tool.ID]
		if !exists {
			continue
		}
		if tool.Parser != parser {
			t.Errorf("tool %q parser = %q, want %q", tool.ID, tool.Parser, parser)
		}
		delete(want, tool.ID)
	}
	for tool := range want {
		t.Errorf("checked-in policy is missing tool %q", tool)
	}
}

func TestCheckedInToolProfileMembershipIsExact(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "policies", "tools.yaml"))
	if err != nil {
		t.Fatalf("open checked-in policy: %v", err)
	}
	policy, loadErr := LoadPolicy(file)
	closeErr := file.Close()
	if loadErr != nil || closeErr != nil {
		t.Fatalf("load checked-in policy: %v, close: %v", loadErr, closeErr)
	}
	want := map[string]string{
		"actionlint":        "go-strict,go-library,repository-only",
		"apidiff":           "go-library",
		"checkov":           "go-strict,go-library,repository-only",
		"gitleaks":          "go-strict,go-library,repository-only",
		"go-current":        "go-strict,go-library,release",
		"go-licenses":       "go-strict,go-library,deep,release",
		"go-previous":       "go-strict,go-library",
		"gocover-cobertura": "go-strict,go-library",
		"goimports":         "go-strict,go-library",
		"golangci-lint":     "go-strict,go-library",
		"gopls":             "go-strict,go-library",
		"gotestsum":         "go-strict,go-library",
		"govulncheck":       "go-strict,go-library",
		"gremlins":          "deep",
		"grype":             "deep,release",
		"hadolint":          "go-strict,go-library,repository-only",
		"markdownlint":      "go-strict,go-library,repository-only",
		"osv-scanner":       "go-strict,go-library",
		"semgrep":           "go-strict,go-library,repository-only",
		"shellcheck":        "go-strict,go-library,repository-only",
		"shfmt":             "go-strict,go-library,repository-only",
		"staticcheck":       "go-strict,go-library",
		"syft":              "deep,release",
		"trivy":             "go-strict,go-library,repository-only,deep,release",
		"yamllint":          "go-strict,go-library,repository-only",
		"zizmor":            "go-strict,go-library,repository-only",
	}
	if len(policy.Tools) != len(want) {
		t.Fatalf("tool locks = %d, want %d", len(policy.Tools), len(want))
	}
	for _, tool := range policy.Tools {
		profiles, exists := want[tool.ID]
		if !exists {
			t.Errorf("unexpected tool profile lock %q", tool.ID)
			continue
		}
		if got := strings.Join(tool.Profiles, ","); got != profiles {
			t.Errorf("tool %q profiles = %q, want %q", tool.ID, got, profiles)
		}
		delete(want, tool.ID)
	}
	for tool := range want {
		t.Errorf("missing tool profile lock %q", tool)
	}
}

func TestPolicyDocumentsScannerOwnershipAndV11AdoptionBoundary(t *testing.T) {
	policy := string(mustRead(t, filepath.Join("..", "..", "docs", "policy.md")))
	for _, required := range []string{
		"Scanner Ownership Matrix", "Primary purpose", "Native report and gate behavior", "Triage owner",
		"CodeQL", "Semgrep", "gosec", "govulncheck", "OSV-Scanner", "Trivy", "Grype",
		"GitHub secret scanning", "Gitleaks", "Dependency Review", "Syft",
		"one scanner never suppresses", "execution error remains blocking",
	} {
		if !strings.Contains(policy, required) {
			t.Errorf("policy is missing %q", required)
		}
	}

	for _, name := range []string{"README.md", "docs/adoption.md", "docs/releases.md"} {
		text := string(mustRead(t, filepath.Join("..", "..", filepath.FromSlash(name))))
		for _, required := range []string{"v1.0.0", "v1.1.0", "failed"} {
			if !strings.Contains(text, required) {
				t.Errorf("%s is missing %q", name, required)
			}
		}
	}
	adoption := string(mustRead(t, filepath.Join("..", "..", "docs", "adoption.md")))
	for _, required := range []string{"repository-only", "every Go job was", "fail-closed", "schema 2"} {
		if !strings.Contains(adoption, required) {
			t.Errorf("adoption guide is missing %q", required)
		}
	}
}

func TestGenerateIsDeterministicAndVerifyDetectsDrift(t *testing.T) {
	root := fixtureRoot(t)
	if err := Generate(root); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	first := generatedSnapshot(t, root)
	if err := Generate(root); err != nil {
		t.Fatalf("second Generate() error = %v", err)
	}
	second := generatedSnapshot(t, root)
	if !bytes.Equal(first, second) {
		t.Fatal("repeated generation changed output")
	}
	if err := Verify(root); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	workflow := filepath.Join(root, ".github", "workflows", "go.yml")
	if err := os.WriteFile(workflow, append(mustRead(t, workflow), []byte("# drift\n")...), 0o644); err != nil {
		t.Fatalf("introduce drift: %v", err)
	}
	if err := Verify(root); err == nil || !strings.Contains(err.Error(), ".github/workflows/go.yml") {
		t.Fatalf("Verify(drift) error = %v", err)
	}
}

func TestGeneratedArtifactsRejectUnsafeWorkflowConstructs(t *testing.T) {
	root := fixtureRoot(t)
	if err := Generate(root); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	shaUse := regexp.MustCompile(`uses:\s+[^\s]+@([0-9a-f]{40})`)
	for _, name := range generatedPaths {
		data := mustRead(t, filepath.Join(root, filepath.FromSlash(name)))
		text := string(data)
		for _, forbidden := range []string{"continue-on-error:", "pull_request_target:", "container:", "@main", "@master"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden %q", name, forbidden)
			}
		}
		for line := range strings.SplitSeq(text, "\n") {
			if strings.Contains(line, "uses:") && !strings.Contains(line, "./") && !shaUse.MatchString(line) {
				t.Fatalf("%s has mutable action reference %q", name, line)
			}
		}
		if strings.HasPrefix(name, "templates/callers/generated/") && strings.Contains(text, "paths:") {
			t.Fatalf("required caller %s has a workflow path filter", name)
		}
	}
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"policies/tools.yaml", "policies/linters.yaml"} {
		copyFixture(t, filepath.Join("../..", name), filepath.Join(root, name))
	}
	for _, name := range templatePaths {
		copyFixture(t, filepath.Join("../..", name), filepath.Join(root, name))
	}
	return root
}

func copyFixture(t *testing.T, source, destination string) {
	t.Helper()
	data := mustRead(t, source)
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(destination), err)
	}
	if err := os.WriteFile(destination, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", destination, err)
	}
}

func generatedSnapshot(t *testing.T, root string) []byte {
	t.Helper()
	var result []byte
	for _, name := range generatedPaths {
		result = append(result, []byte(name)...)
		result = append(result, 0)
		result = append(result, mustRead(t, filepath.Join(root, filepath.FromSlash(name)))...)
		result = append(result, 0)
	}
	return result
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}
