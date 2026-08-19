package applicability

import (
	"bytes"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

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
				"json/json/documents":                 evidence.Applicable,
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

func TestIsShellRecognizesSupportedShebangRegardlessOfMode(t *testing.T) {
	tests := []struct {
		name string
		file trackedFile
		want bool
	}{
		{name: "non-executable shebang", file: trackedFile{mode: 0o644, data: []byte("#!/bin/sh\n")}, want: true},
		{name: "executable sh", file: trackedFile{mode: 0o755, data: []byte("#!/bin/sh\n")}, want: true},
		{name: "executable bash", file: trackedFile{mode: 0o755, data: []byte("#!/bin/bash\n")}, want: true},
		{name: "direct options", file: trackedFile{data: []byte("#!/bin/bash -e\n")}, want: true},
		{name: "env split string", file: trackedFile{data: []byte("#!/usr/bin/env -S bash -e\n")}, want: true},
		{name: "env unset short", file: trackedFile{data: []byte("#!/usr/bin/env -u PATH bash\n")}, want: true},
		{name: "env unset long", file: trackedFile{data: []byte("#!/usr/bin/env --unset PATH bash\n")}, want: true},
		{name: "env chdir short", file: trackedFile{data: []byte("#!/usr/bin/env -C /tmp sh\n")}, want: true},
		{name: "env chdir long", file: trackedFile{data: []byte("#!/usr/bin/env --chdir /tmp ksh\n")}, want: true},
		{name: "CRLF", file: trackedFile{data: []byte("#!/usr/bin/env bash\r\n")}, want: true},
		{name: "env without command", file: trackedFile{data: []byte("#!/usr/bin/env\n")}},
		{name: "env option without operand", file: trackedFile{data: []byte("#!/usr/bin/env -u\n")}},
		{name: "direct prefix collision", file: trackedFile{data: []byte("#!/bin/bashful\n")}},
		{name: "env prefix collision", file: trackedFile{data: []byte("#!/usr/bin/env bashful\n")}},
		{name: "unrecognized", file: trackedFile{mode: 0o755, data: []byte("#!/usr/bin/env fish\n")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsShellFile(test.file.path, test.file.data); got != test.want {
				t.Fatalf("IsShellFile() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestReadTrackedFilesEnforcesExactByteLimits(t *testing.T) {
	tests := []struct {
		name    string
		tracked fs.FS
		maxFile int64
		maxTree int64
		wantErr string
	}{
		{name: "exact file and tree", tracked: fstest.MapFS{"file": &fstest.MapFile{Data: []byte("1234")}}, maxFile: 4, maxTree: 4},
		{name: "reported file too large", tracked: singleFileFS{data: []byte("1"), reportedSize: 5}, maxFile: 4, maxTree: 8, wantErr: "exceeds 4 bytes"},
		{name: "payload larger than reported size", tracked: singleFileFS{data: []byte("12345"), reportedSize: 4}, maxFile: 4, maxTree: 8, wantErr: "exceeds 4 bytes"},
		{name: "exact aggregate", tracked: fstest.MapFS{"a": &fstest.MapFile{Data: []byte("1234")}, "b": &fstest.MapFile{Data: []byte("5678")}}, maxFile: 4, maxTree: 8},
		{name: "aggregate overflow", tracked: fstest.MapFS{"a": &fstest.MapFile{Data: []byte("1234")}, "b": &fstest.MapFile{Data: []byte("5678")}, "c": &fstest.MapFile{Data: []byte("9")}}, maxFile: 4, maxTree: 8, wantErr: "tracked tree exceeds 8 bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := readTrackedFilesWithLimits(test.tracked, test.maxFile, test.maxTree)
			if test.wantErr == "" && err != nil {
				t.Fatalf("readTrackedFilesWithLimits() error = %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("readTrackedFilesWithLimits() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestInspectClassifiesExactFileShapes(t *testing.T) {
	tests := []struct {
		name string
		file trackedFile
		want repositoryShape
	}{
		{name: "workflow yml", file: trackedFile{path: ".github/workflows/ci.yml"}, want: repositoryShape{workflow: true, yaml: true}},
		{name: "workflow yaml", file: trackedFile{path: ".github/workflows/ci.yaml"}, want: repositoryShape{workflow: true, yaml: true}},
		{name: "yaml outside workflow", file: trackedFile{path: "ci.yml"}, want: repositoryShape{yaml: true}},
		{name: "extensionless workflow", file: trackedFile{path: ".github/workflows/ci"}, want: repositoryShape{}},
		{name: "markdown long extension", file: trackedFile{path: "README.markdown"}, want: repositoryShape{markdown: true}},
		{name: "markdown short extension", file: trackedFile{path: "README.md"}, want: repositoryShape{markdown: true}},
		{name: "JSON", file: trackedFile{path: "data.json"}, want: repositoryShape{json: true}},
		{name: "unrelated", file: trackedFile{path: "data.txt"}, want: repositoryShape{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := inspect([]trackedFile{test.file}, nil); !repositoryShapesEqual(got, test.want) {
				t.Fatalf("inspect() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestIsGeneratedUsesDirectoryBoundaries(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{
		{name: "generated", want: true},
		{name: "generated/file.go", want: true},
		{name: "generated-other/file.go", want: false},
		{name: "other/file.go", want: false},
	} {
		if got := isGenerated(test.name, []string{"generated"}); got != test.want {
			t.Errorf("isGenerated(%q) = %t, want %t", test.name, got, test.want)
		}
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

func repositoryShapesEqual(left, right repositoryShape) bool {
	return slices.Equal(left.modules, right.modules) &&
		left.ordinaryGo == right.ordinaryGo &&
		left.shell == right.shell &&
		left.docker == right.docker &&
		left.workflow == right.workflow &&
		left.terraform == right.terraform &&
		left.markdown == right.markdown &&
		left.yaml == right.yaml &&
		left.json == right.json
}

type singleFileFS struct {
	data         []byte
	reportedSize int64
}

func (filesystem singleFileFS) Open(name string) (fs.File, error) {
	switch name {
	case ".":
		return &singleDirectory{entry: singleDirEntry{info: singleFileInfo{name: "file", size: filesystem.reportedSize}}}, nil
	case "file":
		return &singleRegularFile{Reader: bytes.NewReader(filesystem.data), info: singleFileInfo{name: "file", size: filesystem.reportedSize}}, nil
	default:
		return nil, fs.ErrNotExist
	}
}

type singleDirectory struct {
	entry singleDirEntry
	read  bool
}

func (*singleDirectory) Read([]byte) (int, error) { return 0, io.EOF }
func (*singleDirectory) Close() error             { return nil }
func (*singleDirectory) Stat() (fs.FileInfo, error) {
	return singleFileInfo{name: ".", mode: fs.ModeDir | 0o755}, nil
}

func (directory *singleDirectory) ReadDir(count int) ([]fs.DirEntry, error) {
	if directory.read {
		if count > 0 {
			return nil, io.EOF
		}
		return nil, nil
	}
	directory.read = true
	return []fs.DirEntry{directory.entry}, nil
}

type singleRegularFile struct {
	*bytes.Reader
	info singleFileInfo
}

func (*singleRegularFile) Close() error { return nil }
func (file *singleRegularFile) Stat() (fs.FileInfo, error) {
	return file.info, nil
}

type singleDirEntry struct{ info singleFileInfo }

func (entry singleDirEntry) Name() string               { return entry.info.Name() }
func (singleDirEntry) IsDir() bool                      { return false }
func (singleDirEntry) Type() fs.FileMode                { return 0 }
func (entry singleDirEntry) Info() (fs.FileInfo, error) { return entry.info, nil }

type singleFileInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (info singleFileInfo) Name() string      { return info.name }
func (info singleFileInfo) Size() int64       { return info.size }
func (info singleFileInfo) Mode() fs.FileMode { return info.mode }
func (singleFileInfo) ModTime() time.Time     { return time.Time{} }
func (info singleFileInfo) IsDir() bool       { return info.mode.IsDir() }
func (singleFileInfo) Sys() any               { return nil }

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
