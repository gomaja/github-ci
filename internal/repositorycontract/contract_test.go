package repositorycontract

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/generate"
)

var immutableUse = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$`)

func TestRepositoryRequiredFiles(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	files := []string{
		"LICENSE", "README.md", "CONTRIBUTING.md", "SECURITY.md", "Makefile", ".gitattributes",
		".github/CODEOWNERS", ".github/dependabot.yml", ".github/github-ci.yaml",
		".github/workflows/ci.yml", ".github/workflows/deep-schedule.yml",
		".github/workflows/go.yml", ".github/workflows/deep.yml", ".github/workflows/release.yml",
		".golangci.yml", ".markdownlint-cli2.yaml",
		"docs/adoption.md", "docs/exceptions.md", "docs/governance.md", "docs/policy.md",
		"docs/releases.md", "docs/security-model.md", "docs/troubleshooting.md",
	}
	for _, name := range files {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(name))); err != nil || info.IsDir() {
			t.Errorf("required file %s is missing", name)
		}
	}
}

func TestRepositoryWorkflowUsesAreImmutable(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	workflows, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(workflows) < 5 {
		t.Fatalf("workflow count = %d, want at least 5", len(workflows))
	}
	for _, name := range workflows {
		file, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "uses:") && !strings.Contains(line, " uses:") {
				continue
			}
			_, value, found := strings.Cut(line, "uses:")
			if !found {
				continue
			}
			value = strings.TrimSpace(value)
			if !strings.HasPrefix(value, "./") && !immutableUse.MatchString(value) {
				t.Errorf("%s contains mutable or invalid action use %q", filepath.Base(name), value)
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, forbidden := range []string{"pull_request_target:", "permissions: write-all", "curl | sh", "curl|sh"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s contains forbidden workflow pattern %q", filepath.Base(name), forbidden)
			}
		}
	}
}

func TestRepositoryScannerInventory(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	file, err := os.Open(filepath.Join(root, "policies", "tools.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("close tool policy: %v", err)
		}
	})
	policy, err := generate.LoadPolicy(file)
	if err != nil {
		t.Fatalf("load tool policy: %v", err)
	}
	identities := make([]string, 0, len(policy.Actions)+len(policy.Tools))
	for _, action := range policy.Actions {
		identities = append(identities, action.ID)
	}
	for _, tool := range policy.Tools {
		identities = append(identities, tool.ID)
	}
	for _, id := range []string{
		"actionlint", "apidiff", "checkov", "codeql", "dependency-review", "gitleaks",
		"golangci-lint", "goimports", "gopls", "govulncheck", "gremlins", "grype",
		"hadolint", "markdownlint", "osv-scanner", "scorecard", "semgrep", "shellcheck",
		"shfmt", "staticcheck", "syft", "trivy", "yamllint", "zizmor",
	} {
		found := false
		for _, identity := range identities {
			found = found || identity == id || strings.HasPrefix(identity, id+"-")
		}
		if !found {
			t.Errorf("tool policy is missing %s", id)
		}
	}
}

func TestGovernanceUsesRepositoryOnlyProfileForShellCanary(t *testing.T) {
	t.Parallel()
	file, err := os.Open(filepath.Join(repositoryRoot(t), "governance", "gomaja.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("close governance manifest: %v", err)
		}
	})
	manifest, err := config.DecodeGovernance(file)
	if err != nil {
		t.Fatalf("decode governance manifest: %v", err)
	}
	for _, repository := range manifest.Repositories {
		if repository.Name == "sctp-portkill" {
			if repository.Profile != config.ProfileRepositoryOnly {
				t.Fatalf("sctp-portkill profile = %q, want %q", repository.Profile, config.ProfileRepositoryOnly)
			}
			return
		}
	}
	t.Fatal("governance manifest is missing sctp-portkill")
}

func TestRepositoryScannerScriptsFailClosed(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "scripts", "run-scanners.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"set -euo pipefail",
		"osv-scanner scan source --recursive --no-ignore",
		"--skip-version-check --disable-telemetry",
		"--network none --cap-drop ALL --security-opt no-new-privileges --read-only",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("scanner runner is missing fail-closed contract %q", required)
		}
	}
	if count := strings.Count(text, `--user "$(id -u):$(id -g)"`); count != 3 {
		t.Errorf("scanner runner has %d non-root container invocations, want 3", count)
	}
}

func TestScannerInstallerVerifiesGremlinsModuleVersion(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "scripts", "install-scanners.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `go version -m "$BIN_DIR/gremlins"`) ||
		!strings.Contains(text, `github.com/go-gremlins/gremlins\tv0.6.0`) {
		t.Error("scanner installer does not verify the pinned Gremlins module version")
	}
	if strings.Contains(text, `"$BIN_DIR/gremlins" --version`) {
		t.Error("scanner installer relies on the unversioned source-build Gremlins CLI string")
	}
}

func TestExternalReportsAreArchivedBeforeParsing(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "scripts", "record-external.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"archive=", "install -m 0600", "REPORT_PATH=$archive"} {
		if !strings.Contains(text, required) {
			t.Errorf("external report recorder is missing raw archive contract %q", required)
		}
	}
}

func TestRepositoryDocumentationLinksResolve(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	links := regexp.MustCompile(`\[[^]]+\]\(([^)]+)\)`).FindAllStringSubmatch(string(data), -1)
	if len(links) < 8 {
		t.Fatalf("README local link count = %d, want at least 8", len(links))
	}
	for _, match := range links {
		target := strings.Split(match[1], "#")[0]
		if target == "" || strings.Contains(target, "://") {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(target))); err != nil {
			t.Errorf("README link %q does not resolve", match[1])
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
