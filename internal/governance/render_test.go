package governance

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomaja/github-ci/internal/config"
)

func TestRenderCallersPinsExactSHAAndProfile(t *testing.T) {
	t.Parallel()
	manifest := testGovernance()
	manifest.Repositories[0].Profile = config.ProfileGoLibrary
	output := t.TempDir()
	sha := "0123456789abcdef0123456789abcdef01234567"
	if err := RenderCallers(manifest, output, sha, "example"); err != nil {
		t.Fatalf("RenderCallers() error = %v", err)
	}
	root := filepath.Join(output, "gomaja", "example")
	for _, name := range []string{
		".github/github-ci.yaml",
		".github/workflows/github-ci.yml",
		".github/workflows/github-ci-deep.yml",
		".github/workflows/github-ci-release.yml",
	} {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if name != ".github/github-ci.yaml" && !bytes.Contains(data, []byte("@"+sha)) {
			t.Fatalf("%s does not pin %s", name, sha)
		}
		if name == ".github/workflows/github-ci-release.yml" {
			for _, required := range []string{"inputs:", "tag:", "required: true", "type: string", `tag: ${{ inputs.tag }}`} {
				if !bytes.Contains(data, []byte(required)) {
					t.Fatalf("%s does not forward manual tag input %q", name, required)
				}
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(root, ".github", "github-ci.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := config.DecodeConsumer(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecodeConsumer() error = %v", err)
	}
	if consumer.Profile != config.ProfileGoLibrary {
		t.Fatalf("Profile = %q, want go-library", consumer.Profile)
	}
}

func TestStandardCallerHasNoDuplicatedProfileInput(t *testing.T) {
	caller := standardCaller("0123456789abcdef0123456789abcdef01234567")
	if strings.Contains(caller, "profile:") || strings.Contains(caller, "with:") {
		t.Fatalf("standard caller duplicates consumer configuration:\n%s", caller)
	}
	data, err := os.ReadFile("../../templates/callers/generated/github-ci.yml")
	if err != nil {
		t.Fatalf("read generated standard caller: %v", err)
	}
	if bytes.Contains(data, []byte("profile:")) || bytes.Contains(data, []byte("with:")) {
		t.Fatalf("generated standard caller duplicates consumer configuration:\n%s", data)
	}
}

func TestPreparationTemplatesKeepRepositoryBehaviorConsumerOwned(t *testing.T) {
	tests := []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{
			name: "generated-source.yml.tmpl",
			required: []string{
				"./scripts/generate.sh", "git diff --exit-code", "Replace this command",
			},
		},
		{
			name: "postgresql.yml.tmpl",
			required: []string{
				"postgres:18.1@sha256:1090bc3a8ccfb0b55f78a494d76f8d603434f7e4553543d6e807bc7bd6bbd17f",
				"./scripts/test-postgresql.sh", "Replace this command",
			},
		},
		{
			name: "redis.yml.tmpl",
			required: []string{
				"redis:8.6.1@sha256:315270d166080f537bbdf1b489b603aaaa213cb55a544acfa51feb7481abb1c0",
				"./scripts/test-redis.sh", "Replace this command",
			},
		},
		{
			name: "private-modules.yml.tmpl",
			required: []string{
				"github.event.pull_request.head.repo.full_name == github.repository", "PRIVATE_MODULE_TOKEN",
				"GOPRIVATE", "Fork pull requests cannot receive",
			},
			forbidden: []string{"pull_request_target"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../templates/preparation", test.name))
			if err != nil {
				t.Fatalf("read template: %v", err)
			}
			for _, required := range test.required {
				if !bytes.Contains(data, []byte(required)) {
					t.Errorf("template is missing %q", required)
				}
			}
			for _, forbidden := range test.forbidden {
				if bytes.Contains(data, []byte(forbidden)) {
					t.Errorf("template contains forbidden %q", forbidden)
				}
			}
		})
	}
}

func TestRenderCallersRejectsMutableReference(t *testing.T) {
	t.Parallel()
	err := RenderCallers(testGovernance(), t.TempDir(), "main", "example")
	if err == nil || !strings.Contains(err.Error(), "immutable 40-character") {
		t.Fatalf("RenderCallers() error = %v", err)
	}
}

func TestRenderCallersFiltersMultipleRepositories(t *testing.T) {
	manifest := testGovernance()
	manifest.Repositories = append(manifest.Repositories, config.Repository{Name: "selected", Owner: "gomaja"})
	output := t.TempDir()
	sha := "0123456789abcdef0123456789abcdef01234567"
	if err := RenderCallers(manifest, output, sha, "selected"); err != nil {
		t.Fatalf("RenderCallers() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(output, "gomaja", "example")); !os.IsNotExist(err) {
		t.Fatalf("unselected repository stat error = %v, want not-exist", err)
	}
	if _, err := os.Stat(filepath.Join(output, "gomaja", "selected", ".github", "github-ci.yaml")); err != nil {
		t.Fatalf("selected repository stat error = %v", err)
	}
}

func TestPlanDecodingRejectsTampering(t *testing.T) {
	t.Parallel()
	plan := Plan{SchemaVersion: "1", APIVersion: "2026-03-10", ObservedHash: strings.Repeat("a", 64), Operations: []Operation{}}
	plan.ID = planDigest(plan)
	data, err := marshalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePlan(data); err != nil {
		t.Fatalf("decodePlan(valid) error = %v", err)
	}
	for _, malformed := range [][]byte{
		bytes.Replace(data, []byte(`"api_version": "2026-03-10"`), []byte(`"api_version": "2025-01-01"`), 1),
		append(bytes.Clone(data), []byte(`{}`)...),
		bytes.Replace(data, []byte(`"operations"`), []byte(`"unknown"`), 1),
	} {
		if _, err := decodePlan(malformed); err == nil {
			t.Fatalf("decodePlan(%q) error = nil", malformed)
		}
	}
}

func TestGovernanceCLINoCommand(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if code := RunCLI(context.Background(), nil, &bytes.Buffer{}, &stderr); code != 2 {
		t.Fatalf("RunCLI() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func FuzzPlanDecoding(f *testing.F) {
	plan := Plan{SchemaVersion: "1", APIVersion: "2026-03-10", ObservedHash: strings.Repeat("a", 64), Operations: []Operation{}}
	plan.ID = planDigest(plan)
	valid, err := marshalPlan(plan)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{valid, {}, []byte(`{}`), []byte(`{"id":`), append(bytes.Clone(valid), []byte(`{}`)...)} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = decodePlan(data)
	})
}
