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

func TestRenderCallersRejectsMutableReference(t *testing.T) {
	t.Parallel()
	err := RenderCallers(testGovernance(), t.TempDir(), "main", "example")
	if err == nil || !strings.Contains(err.Error(), "immutable 40-character") {
		t.Fatalf("RenderCallers() error = %v", err)
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
