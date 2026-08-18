package applicability

import (
	"io/fs"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/evidence"
)

const (
	testSubjectSHA = "0123456789abcdef0123456789abcdef01234567"
	testPolicySHA  = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)

func TestDetectRepositoryShapes(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		consumer config.Consumer
		expected map[string]evidence.Applicability
		reasons  map[string]string
	}{
		{
			name:     "go single module",
			fixture:  "go-single",
			consumer: consumer(config.ProfileGoLibrary),
			expected: map[string]evidence.Applicability{
				"staticcheck/staticcheck/default": evidence.Applicable,
				"gofmt/gofmt/tracked-go":          evidence.Applicable,
				"hadolint/hadolint/dockerfiles":   evidence.NotApplicable,
			},
			reasons: map[string]string{"hadolint/hadolint/dockerfiles": ReasonNoDockerfiles},
		},
		{
			name:    "go multi module",
			fixture: "go-multi",
			consumer: func() config.Consumer {
				value := consumer(config.ProfileGoStrict)
				value.Modules = []config.Module{".", "services/api"}
				return value
			}(),
			expected: map[string]evidence.Applicability{
				"go/go/module-integrity": evidence.Applicable,
			},
		},
		{
			name:    "generated Go only",
			fixture: "go-generated",
			consumer: func() config.Consumer {
				value := consumer(config.ProfileGoLibrary)
				value.Generated = []string{"generated"}
				return value
			}(),
			expected: map[string]evidence.Applicability{
				"go/go/build":            evidence.Applicable,
				"gofmt/gofmt/tracked-go": evidence.NotApplicable,
			},
			reasons: map[string]string{"gofmt/gofmt/tracked-go": ReasonNoOrdinaryGoFiles},
		},
		{
			name:     "shell only",
			fixture:  "shell-only",
			consumer: consumer(config.ProfileRepositoryOnly),
			expected: map[string]evidence.Applicability{
				"shellcheck/shellcheck/scripts": evidence.Applicable,
				"shfmt/shfmt/scripts":           evidence.Applicable,
			},
		},
		{
			name:     "Docker",
			fixture:  "docker",
			consumer: consumer(config.ProfileRepositoryOnly),
			expected: map[string]evidence.Applicability{
				"hadolint/hadolint/dockerfiles": evidence.Applicable,
			},
		},
		{
			name:     "workflow only",
			fixture:  "workflow-only",
			consumer: consumer(config.ProfileRepositoryOnly),
			expected: map[string]evidence.Applicability{
				"actionlint/actionlint/workflows": evidence.Applicable,
				"zizmor/zizmor/workflows":         evidence.Applicable,
			},
		},
		{
			name:     "Terraform",
			fixture:  "terraform",
			consumer: consumer(config.ProfileRepositoryOnly),
			expected: map[string]evidence.Applicability{
				"checkov/checkov/infrastructure": evidence.Applicable,
			},
		},
		{
			name:     "Markdown only",
			fixture:  "markdown-only",
			consumer: consumer(config.ProfileRepositoryOnly),
			expected: map[string]evidence.Applicability{
				"markdownlint/markdownlint/documents": evidence.Applicable,
				"shellcheck/shellcheck/scripts":       evidence.NotApplicable,
			},
		},
		{
			name:     "mixed",
			fixture:  "mixed",
			consumer: consumer(config.ProfileGoStrict),
			expected: map[string]evidence.Applicability{
				"staticcheck/staticcheck/default":     evidence.Applicable,
				"shellcheck/shellcheck/scripts":       evidence.Applicable,
				"hadolint/hadolint/dockerfiles":       evidence.Applicable,
				"actionlint/actionlint/workflows":     evidence.Applicable,
				"checkov/checkov/infrastructure":      evidence.Applicable,
				"markdownlint/markdownlint/documents": evidence.Applicable,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := Detect(os.DirFS("../../testdata/repositories/"+test.fixture), Input{
				Consumer:     test.consumer,
				SubjectSHA:   testSubjectSHA,
				PolicySHA256: testPolicySHA,
				Catalog:      DefaultCatalog(),
			})
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if err := evidence.ValidatePlan(plan); err != nil {
				t.Fatalf("ValidatePlan() error = %v", err)
			}
			assertExpected(t, plan, test.expected, test.reasons)
			assertUniqueSorted(t, plan.Expected)
			assertCompleteProfilePlan(t, plan, test.consumer.Profile)
		})
	}
}

func TestDetectRecognizesShellAndDockerfileVariants(t *testing.T) {
	tracked := fstest.MapFS{
		"scripts/extension.bash":    &fstest.MapFile{Data: []byte("true\n")},
		"scripts/executable":        &fstest.MapFile{Data: []byte("#!/bin/sh\ntrue\n"), Mode: 0o755},
		"containers/Containerfile":  &fstest.MapFile{Data: []byte("FROM scratch\n")},
		"containers/Dockerfile.dev": &fstest.MapFile{Data: []byte("FROM scratch\n")},
		"containers/api.Dockerfile": &fstest.MapFile{Data: []byte("FROM scratch\n")},
	}
	plan, err := Detect(tracked, validInput(config.ProfileRepositoryOnly))
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	assertExpected(t, plan, map[string]evidence.Applicability{
		"shellcheck/shellcheck/scripts": evidence.Applicable,
		"hadolint/hadolint/dockerfiles": evidence.Applicable,
	}, nil)
}

func TestDetectRecognizesDirectExecutableShellShebangs(t *testing.T) {
	for _, shebang := range []string{"#!/bin/ksh\n", "#!/bin/zsh\n"} {
		t.Run(strings.TrimSpace(shebang), func(t *testing.T) {
			tracked := fstest.MapFS{"script": &fstest.MapFile{Data: []byte(shebang + "true\n"), Mode: 0o755}}
			plan := mustDetect(t, tracked, validInput(config.ProfileRepositoryOnly))
			assertExpected(t, plan, map[string]evidence.Applicability{
				"shellcheck/shellcheck/scripts": evidence.Applicable,
				"shfmt/shfmt/scripts":           evidence.Applicable,
			}, nil)
		})
	}
}

func TestDetectIsDeterministicAcrossCatalogInsertionOrder(t *testing.T) {
	tracked := fstest.MapFS{
		"go.mod":  &fstest.MapFile{Data: []byte("module example.com/deterministic\n\ngo 1.25\n")},
		"main.go": &fstest.MapFile{Data: []byte("package deterministic\n")},
	}
	input := validInput(config.ProfileGoStrict)
	first, err := Detect(tracked, input)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatalf("first Digest() error = %v", err)
	}

	for range 20 {
		shuffled := slices.Clone(input.Catalog)
		rand.Shuffle(len(shuffled), func(left, right int) {
			shuffled[left], shuffled[right] = shuffled[right], shuffled[left]
		})
		input.Catalog = shuffled
		plan, detectErr := Detect(tracked, input)
		if detectErr != nil {
			t.Fatalf("Detect() with shuffled catalog error = %v", detectErr)
		}
		digest, digestErr := plan.Digest()
		if digestErr != nil {
			t.Fatalf("Digest() error = %v", digestErr)
		}
		if digest != firstDigest {
			t.Fatalf("Digest() = %q, want %q", digest, firstDigest)
		}
	}
}

func TestDetectRejectsCatalogPolicyDrift(t *testing.T) {
	input := validInput(config.ProfileGoStrict)
	for index := range input.Catalog {
		if input.Catalog[index].Tool == "staticcheck" {
			input.Catalog[index].ReasonCode = ReasonNoDockerfiles
			break
		}
	}
	_, err := Detect(fstest.MapFS{
		"go.mod":  &fstest.MapFile{Data: []byte("module example.com/drift\n")},
		"main.go": &fstest.MapFile{Data: []byte("package drift\n")},
	}, input)
	if err == nil || !strings.Contains(err.Error(), "catalog policy drift") {
		t.Fatalf("Detect() error = %v", err)
	}
}

func TestDetectTreeDigestBindsPathModeAndContent(t *testing.T) {
	base := fstest.MapFS{"script.sh": &fstest.MapFile{Data: []byte("true\n"), Mode: 0o644}}
	first := mustDetect(t, base, validInput(config.ProfileRepositoryOnly))
	tests := []fstest.MapFS{
		{"renamed.sh": &fstest.MapFile{Data: []byte("true\n"), Mode: 0o644}},
		{"script.sh": &fstest.MapFile{Data: []byte("nope\n"), Mode: 0o644}},
		{"script.sh": &fstest.MapFile{Data: []byte("true\n"), Mode: 0o755}},
	}
	for index, tracked := range tests {
		plan := mustDetect(t, tracked, validInput(config.ProfileRepositoryOnly))
		if plan.TreeSHA256 == first.TreeSHA256 {
			t.Errorf("mutation %d TreeSHA256 = %q, want changed digest", index, plan.TreeSHA256)
		}
	}
}

func TestDetectRejectsInvalidOrContradictoryInput(t *testing.T) {
	tests := []struct {
		name    string
		tracked fs.FS
		input   Input
		want    string
	}{
		{name: "invalid subject", tracked: fstest.MapFS{"README.md": &fstest.MapFile{}}, input: func() Input {
			value := validInput(config.ProfileRepositoryOnly)
			value.SubjectSHA = "ABC"
			return value
		}(), want: "subject_sha"},
		{name: "invalid policy", tracked: fstest.MapFS{"README.md": &fstest.MapFile{}}, input: func() Input {
			value := validInput(config.ProfileRepositoryOnly)
			value.PolicySHA256 = "sha256:bad"
			return value
		}(), want: "policy_sha256"},
		{name: "symlink", tracked: fstest.MapFS{"link": &fstest.MapFile{Mode: fs.ModeSymlink}}, input: validInput(config.ProfileRepositoryOnly), want: "symlink"},
		{name: "special file", tracked: fstest.MapFS{"device": &fstest.MapFile{Mode: fs.ModeDevice}}, input: validInput(config.ProfileRepositoryOnly), want: "unsupported file mode"},
		{name: "go profile without module", tracked: fstest.MapFS{"main.go": &fstest.MapFile{Data: []byte("package main\n")}}, input: validInput(config.ProfileGoStrict), want: "requires a tracked go.mod"},
		{name: "repository profile with module", tracked: fstest.MapFS{"go.mod": &fstest.MapFile{Data: []byte("module example.com/bad\n")}}, input: validInput(config.ProfileRepositoryOnly), want: "would omit tracked Go modules"},
		{name: "configured module missing", tracked: fstest.MapFS{"go.mod": &fstest.MapFile{Data: []byte("module example.com/root\n")}}, input: func() Input {
			value := validInput(config.ProfileGoStrict)
			value.Consumer.Modules = []config.Module{".", "missing"}
			return value
		}(), want: "configured module"},
		{name: "tracked module omitted", tracked: fstest.MapFS{"go.mod": &fstest.MapFile{}, "services/api/go.mod": &fstest.MapFile{}}, input: func() Input {
			value := validInput(config.ProfileGoStrict)
			value.Consumer.Modules = []config.Module{"."}
			return value
		}(), want: "omits tracked module"},
		{name: "exceptions manifest not tracked", tracked: fstest.MapFS{"README.md": &fstest.MapFile{}}, input: func() Input {
			value := validInput(config.ProfileRepositoryOnly)
			value.Consumer.Exceptions = ".github/github-ci-exceptions.yml"
			return value
		}(), want: "exceptions manifest"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Detect(test.tracked, test.input)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Detect() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDetectUsesOnlyTheSuppliedTrackedFilesystem(t *testing.T) {
	withoutDocker := fstest.MapFS{"README.md": &fstest.MapFile{Data: []byte("# tracked\n")}}
	plan := mustDetect(t, withoutDocker, validInput(config.ProfileRepositoryOnly))
	assertExpected(t, plan, map[string]evidence.Applicability{
		"hadolint/hadolint/dockerfiles": evidence.NotApplicable,
	}, map[string]string{"hadolint/hadolint/dockerfiles": ReasonNoDockerfiles})
}

func consumer(profile config.Profile) config.Consumer {
	return config.Consumer{SchemaVersion: 1, Profile: profile}
}

func validInput(profile config.Profile) Input {
	return Input{
		Consumer:     consumer(profile),
		SubjectSHA:   testSubjectSHA,
		PolicySHA256: testPolicySHA,
		Catalog:      DefaultCatalog(),
	}
}

func mustDetect(t *testing.T, tracked fs.FS, input Input) evidence.Plan {
	t.Helper()
	plan, err := Detect(tracked, input)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	return plan
}

func assertExpected(t *testing.T, plan evidence.Plan, expected map[string]evidence.Applicability, reasons map[string]string) {
	t.Helper()
	byIdentity := make(map[string]evidence.Expected, len(plan.Expected))
	for _, entry := range plan.Expected {
		byIdentity[entry.Identity()] = entry
	}
	for identity, want := range expected {
		got, ok := byIdentity[identity]
		if !ok {
			t.Errorf("plan missing expected identity %q", identity)
			continue
		}
		if got.Applicability != want {
			t.Errorf("%s applicability = %q, want %q", identity, got.Applicability, want)
		}
		if reason, exists := reasons[identity]; exists && got.ReasonCode != reason {
			t.Errorf("%s reason = %q, want %q", identity, got.ReasonCode, reason)
		}
	}
}

func assertUniqueSorted(t *testing.T, expected []evidence.Expected) {
	t.Helper()
	seen := make(map[string]struct{}, len(expected))
	previous := ""
	for _, entry := range expected {
		identity := entry.Identity()
		if _, exists := seen[identity]; exists {
			t.Errorf("duplicate identity %q", identity)
		}
		if previous != "" && strings.Compare(previous, identity) >= 0 {
			t.Errorf("identities not sorted: %q before %q", previous, identity)
		}
		seen[identity] = struct{}{}
		previous = identity
	}
}

func assertCompleteProfilePlan(t *testing.T, plan evidence.Plan, profile config.Profile) {
	t.Helper()
	want := make([]string, 0)
	for _, entry := range DefaultCatalog() {
		if slices.Contains(entry.Profiles, profile) {
			want = append(want, entry.Tool+"/"+entry.CommandID)
		}
	}
	slices.Sort(want)
	got := make([]string, 0, len(plan.Expected))
	for _, entry := range plan.Expected {
		got = append(got, entry.Identity())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("plan identities = %#v, want complete profile identities %#v", got, want)
	}
}
