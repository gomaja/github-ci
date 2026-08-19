package config

import (
	"strings"
	"testing"
)

const validConsumerV2 = `schema-version: 2
profile: go-library
go:
  defaults:
    packages: [./...]
    module-mode: readonly
    build-tags: [sqlite, integration]
    test-timeout: 10m
    package-parallelism: 4
    race-parallelism: 1
    coverage-packages: [./...]
  modules:
    - path: .
    - path: tools
      packages: [./cmd/...]
      module-mode: vendor
      build-tags: [tooling]
      test-timeout: 15m
      package-parallelism: 2
      race-parallelism: 1
      coverage-packages: []
generated-paths: [internal/generated]
exceptions: .github/github-ci-exceptions.yaml
`

func TestDecodeConsumerV2ExecutionContract(t *testing.T) {
	consumer := decodeValidConsumerV2(t)
	if consumer.SchemaVersion != 2 || consumer.Profile != ProfileGoLibrary {
		t.Fatalf("consumer identity = (%d, %q), want (2, go-library)", consumer.SchemaVersion, consumer.Profile)
	}
	if consumer.Go == nil {
		t.Fatal("Go = nil")
	}
	if got := strings.Join(consumer.GeneratedPaths, ","); got != "internal/generated" {
		t.Fatalf("generated paths = %q, want internal/generated", got)
	}
}

func TestDecodeConsumerV2Defaults(t *testing.T) {
	consumer := decodeValidConsumerV2(t)
	defaults := consumer.Go.Defaults
	if defaults.Packages == nil {
		t.Fatal("default packages = nil")
	}
	if got := strings.Join(*defaults.Packages, ","); got != "./..." {
		t.Fatalf("default packages = %q, want ./...", got)
	}
	if defaults.ModuleMode == nil || *defaults.ModuleMode != ModuleModeReadonly {
		t.Fatalf("default module mode = %v, want readonly", defaults.ModuleMode)
	}
	if defaults.BuildTags == nil {
		t.Fatal("default build tags = nil")
	}
	if got := strings.Join(*defaults.BuildTags, ","); got != "sqlite,integration" {
		t.Fatalf("default build tags = %q, want sqlite,integration", got)
	}
	if defaults.TestTimeout == nil || *defaults.TestTimeout != "10m" {
		t.Fatalf("default test timeout = %v, want 10m", defaults.TestTimeout)
	}
	if defaults.PackageParallelism == nil || *defaults.PackageParallelism != 4 {
		t.Fatalf("default package parallelism = %v, want 4", defaults.PackageParallelism)
	}
	if defaults.RaceParallelism == nil || *defaults.RaceParallelism != 1 {
		t.Fatalf("default race parallelism = %v, want 1", defaults.RaceParallelism)
	}
	if defaults.CoveragePackages == nil || strings.Join(*defaults.CoveragePackages, ",") != "./..." {
		t.Fatalf("default coverage = %v, want explicit ./...", defaults.CoveragePackages)
	}
}

func TestDecodeConsumerV2ModuleOverrides(t *testing.T) {
	consumer := decodeValidConsumerV2(t)
	if len(consumer.Go.Modules) != 2 || consumer.Go.Modules[1].Path != "tools" {
		t.Fatalf("modules = %#v, want root and tools", consumer.Go.Modules)
	}
	tools := consumer.Go.Modules[1]
	if tools.CoveragePackages == nil || *tools.CoveragePackages == nil || len(*tools.CoveragePackages) != 0 {
		t.Fatalf("tools coverage = %#v, want explicit empty", tools.CoveragePackages)
	}
}

func decodeValidConsumerV2(t *testing.T) Consumer {
	t.Helper()
	consumer, err := DecodeConsumer(strings.NewReader(validConsumerV2))
	if err != nil {
		t.Fatalf("DecodeConsumer() error = %v", err)
	}
	return consumer
}

func TestDecodeConsumerV2RejectsInvalidExecutionSettings(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "schema 1", yaml: strings.Replace(validConsumerV2, "schema-version: 2", "schema-version: 1", 1), want: "schema-version must be 2"},
		{name: "removed services", yaml: validConsumerV2 + "services: [postgresql]\n", want: "field services not found"},
		{name: "removed generated", yaml: validConsumerV2 + "generated: [internal/generated]\n", want: "field generated not found"},
		{name: "repository only Go", yaml: strings.Replace(validConsumerV2, "profile: go-library", "profile: repository-only", 1), want: "repository-only profile must not configure Go"},
		{name: "duplicate module", yaml: strings.Replace(validConsumerV2, "    - path: tools", "    - path: .", 1), want: "duplicate module"},
		{name: "duplicate packages", yaml: strings.Replace(validConsumerV2, "packages: [./...]", "packages: [./..., ./...]", 1), want: "duplicate package"},
		{name: "empty packages", yaml: strings.Replace(validConsumerV2, "packages: [./...]", "packages: []", 1), want: "packages must not be empty"},
		{name: "duplicate tags", yaml: strings.Replace(validConsumerV2, "build-tags: [sqlite, integration]", "build-tags: [sqlite, sqlite]", 1), want: "duplicate build tag"},
		{name: "duplicate coverage", yaml: strings.Replace(validConsumerV2, "coverage-packages: [./...]", "coverage-packages: [./..., ./...]", 1), want: "duplicate coverage package"},
		{name: "unknown module mode", yaml: strings.Replace(validConsumerV2, "module-mode: readonly", "module-mode: cached", 1), want: "unsupported module mode"},
		{name: "zero timeout", yaml: strings.Replace(validConsumerV2, "test-timeout: 10m", "test-timeout: 0s", 1), want: "test-timeout must be positive"},
		{name: "negative timeout", yaml: strings.Replace(validConsumerV2, "test-timeout: 10m", "test-timeout: -1s", 1), want: "test-timeout must be positive"},
		{name: "excessive timeout", yaml: strings.Replace(validConsumerV2, "test-timeout: 10m", "test-timeout: 46m", 1), want: "test-timeout must not exceed 45m"},
		{name: "malformed timeout", yaml: strings.Replace(validConsumerV2, "test-timeout: 10m", "test-timeout: soon", 1), want: "invalid test-timeout"},
		{name: "zero package parallelism", yaml: strings.Replace(validConsumerV2, "package-parallelism: 4", "package-parallelism: 0", 1), want: "package-parallelism must be between 1 and 64"},
		{name: "excessive package parallelism", yaml: strings.Replace(validConsumerV2, "package-parallelism: 4", "package-parallelism: 65", 1), want: "package-parallelism must be between 1 and 64"},
		{name: "zero race parallelism", yaml: strings.Replace(validConsumerV2, "race-parallelism: 1", "race-parallelism: 0", 1), want: "race-parallelism must be between 1 and 16"},
		{name: "excessive race parallelism", yaml: strings.Replace(validConsumerV2, "race-parallelism: 1", "race-parallelism: 17", 1), want: "race-parallelism must be between 1 and 16"},
		{name: "duplicate generated path", yaml: strings.Replace(validConsumerV2, "[internal/generated]", "[internal/generated, internal/generated]", 1), want: "duplicate generated path"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeConsumer(strings.NewReader(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("DecodeConsumer() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDecodeConsumerV2RejectsUnsafePackagePatterns(t *testing.T) {
	patterns := []string{
		"-run=TestOnly",
		"./../outside",
		"./...;touch",
		"example.com/module@latest",
		`internal\package`,
		"internal package",
		"/absolute/package",
		"$(touch-owned)",
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			yaml := strings.Replace(validConsumerV2, "packages: [./...]", "packages: [\""+strings.ReplaceAll(pattern, `\`, `\\`)+"\"]", 1)
			_, err := DecodeConsumer(strings.NewReader(yaml))
			if err == nil || !strings.Contains(err.Error(), "invalid package pattern") {
				t.Fatalf("DecodeConsumer(%q) error = %v, want invalid package pattern", pattern, err)
			}
		})
	}
}
