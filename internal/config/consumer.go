// Package config defines strict consumer and governance configuration contracts.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
	"unicode"

	"github.com/gomaja/github-ci/internal/pathpolicy"
	"gopkg.in/yaml.v3"
)

const schemaVersion = 2

var (
	buildTagPattern = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)
	packagePattern  = regexp.MustCompile(`^(?:\.|[A-Za-z0-9_][A-Za-z0-9_.-]*)(?:/(?:\.\.\.|[A-Za-z0-9_][A-Za-z0-9_.-]*))*$`)
)

const (
	maxModules         = 128
	maxPackages        = 256
	maxBuildTags       = 64
	maxGeneratedPaths  = 128
	maxTestTimeout     = 45 * time.Minute
	maxPackageParallel = 64
	maxRaceParallel    = 16
)

// Profile identifies the fixed assurance profile applied to a consumer.
type Profile string

const (
	// ProfileGoStrict and the following values select fixed assurance profiles.
	ProfileGoStrict Profile = "go-strict"
	// ProfileGoLibrary applies the public-library compatibility profile.
	ProfileGoLibrary Profile = "go-library"
	// ProfileRepositoryOnly applies repository scanners without Go analyzers.
	ProfileRepositoryOnly Profile = "repository-only"
)

// Module is a repository-relative Go module path.
type Module string

// ModuleMode controls how Go resolves module dependencies.
type ModuleMode string

const (
	// ModuleModeReadonly prevents implicit go.mod and go.sum changes.
	ModuleModeReadonly ModuleMode = "readonly"
	// ModuleModeVendor resolves dependencies from the vendor tree.
	ModuleModeVendor ModuleMode = "vendor"
	// ModuleModeMod permits the Go command to update module metadata when needed.
	ModuleModeMod ModuleMode = "mod"
)

// GoSettings contains inheritable Go execution controls. Pointer-valued fields
// preserve the difference between an omitted value and an explicit zero or
// empty list during strict YAML decoding.
type GoSettings struct {
	Packages           *[]string   `yaml:"packages,omitempty"`
	ModuleMode         *ModuleMode `yaml:"module-mode,omitempty"`
	BuildTags          *[]string   `yaml:"build-tags,omitempty"`
	TestTimeout        *string     `yaml:"test-timeout,omitempty"`
	PackageParallelism *int        `yaml:"package-parallelism,omitempty"`
	RaceParallelism    *int        `yaml:"race-parallelism,omitempty"`
	CoveragePackages   *[]string   `yaml:"coverage-packages,omitempty"`
}

// GoModule applies optional execution overrides to one tracked Go module.
type GoModule struct {
	Path       Module `yaml:"path"`
	GoSettings `yaml:",inline"`
}

// Go configures default and per-module Go execution behavior.
type Go struct {
	Defaults GoSettings `yaml:"defaults,omitempty"`
	Modules  []GoModule `yaml:"modules,omitempty"`
}

// Consumer configures a reusable workflow consumer.
type Consumer struct {
	SchemaVersion  int      `yaml:"schema-version"`
	Profile        Profile  `yaml:"profile"`
	Go             *Go      `yaml:"go,omitempty"`
	GeneratedPaths []string `yaml:"generated-paths,omitempty"`
	Exceptions     string   `yaml:"exceptions,omitempty"`
}

// DecodeConsumer parses and validates exactly one strict YAML document.
func DecodeConsumer(reader io.Reader) (Consumer, error) {
	var consumer Consumer
	if err := decodeStrictYAML(reader, &consumer); err != nil {
		return Consumer{}, err
	}
	if err := consumer.Validate(); err != nil {
		return Consumer{}, err
	}
	return consumer, nil
}

// Validate verifies the semantic constraints of a consumer configuration.
func (consumer Consumer) Validate() error {
	if consumer.SchemaVersion != schemaVersion {
		return fmt.Errorf("schema-version must be %d", schemaVersion)
	}
	if !isProfile(consumer.Profile) {
		return fmt.Errorf("unsupported profile %q", consumer.Profile)
	}
	if consumer.Profile == ProfileRepositoryOnly && consumer.Go != nil {
		return errors.New("repository-only profile must not configure Go")
	}
	if consumer.Go != nil {
		if err := consumer.Go.validate(); err != nil {
			return err
		}
	}

	if len(consumer.GeneratedPaths) > maxGeneratedPaths {
		return fmt.Errorf("generated paths must not contain more than %d entries", maxGeneratedPaths)
	}
	generatedPaths := make(map[string]struct{}, len(consumer.GeneratedPaths))
	for _, generated := range consumer.GeneratedPaths {
		if err := pathpolicy.Validate("generated path", generated); err != nil {
			return err
		}
		if _, exists := generatedPaths[generated]; exists {
			return fmt.Errorf("duplicate generated path %q", generated)
		}
		generatedPaths[generated] = struct{}{}
	}
	if consumer.Exceptions != "" {
		if err := pathpolicy.Validate("exceptions path", consumer.Exceptions); err != nil {
			return err
		}
	}

	return nil
}

func (goConfig Go) validate() error {
	if err := goConfig.Defaults.validate("Go defaults"); err != nil {
		return err
	}
	if len(goConfig.Modules) > maxModules {
		return fmt.Errorf("modules must not contain more than %d entries", maxModules)
	}
	modules := make(map[Module]struct{}, len(goConfig.Modules))
	for _, module := range goConfig.Modules {
		if err := pathpolicy.Validate("module", string(module.Path)); err != nil {
			return err
		}
		if _, exists := modules[module.Path]; exists {
			return fmt.Errorf("duplicate module %q", module.Path)
		}
		modules[module.Path] = struct{}{}
		if err := module.validate(fmt.Sprintf("module %q", module.Path)); err != nil {
			return err
		}
	}
	return nil
}

func (settings GoSettings) validate(scope string) error {
	if err := validatePackageList(scope+" packages", settings.Packages, false); err != nil {
		return err
	}
	if settings.ModuleMode != nil && !isModuleMode(*settings.ModuleMode) {
		return fmt.Errorf("%s has unsupported module mode %q", scope, *settings.ModuleMode)
	}
	if err := validateBuildTags(scope, settings.BuildTags); err != nil {
		return err
	}
	if settings.TestTimeout != nil {
		duration, err := time.ParseDuration(*settings.TestTimeout)
		if err != nil {
			return fmt.Errorf("%s has invalid test-timeout %q: %w", scope, *settings.TestTimeout, err)
		}
		if duration <= 0 {
			return fmt.Errorf("%s test-timeout must be positive", scope)
		}
		if duration > maxTestTimeout {
			return fmt.Errorf("%s test-timeout must not exceed 45m", scope)
		}
	}
	if settings.PackageParallelism != nil && (*settings.PackageParallelism < 1 || *settings.PackageParallelism > maxPackageParallel) {
		return fmt.Errorf("%s package-parallelism must be between 1 and %d", scope, maxPackageParallel)
	}
	if settings.RaceParallelism != nil && (*settings.RaceParallelism < 1 || *settings.RaceParallelism > maxRaceParallel) {
		return fmt.Errorf("%s race-parallelism must be between 1 and %d", scope, maxRaceParallel)
	}
	return validatePackageList(scope+" coverage packages", settings.CoveragePackages, true)
}

func validatePackageList(field string, values *[]string, allowEmpty bool) error {
	if values == nil {
		return nil
	}
	if len(*values) == 0 && !allowEmpty {
		return errors.New("packages must not be empty")
	}
	if len(*values) > maxPackages {
		return fmt.Errorf("%s must not contain more than %d entries", field, maxPackages)
	}
	seen := make(map[string]struct{}, len(*values))
	for _, value := range *values {
		if !packagePattern.MatchString(value) {
			return fmt.Errorf("invalid package pattern %q", value)
		}
		if _, exists := seen[value]; exists {
			if allowEmpty {
				return fmt.Errorf("duplicate coverage package %q", value)
			}
			return fmt.Errorf("duplicate package %q", value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateBuildTags(scope string, values *[]string) error {
	if values == nil {
		return nil
	}
	if len(*values) > maxBuildTags {
		return fmt.Errorf("%s build tags must not contain more than %d entries", scope, maxBuildTags)
	}
	seen := make(map[string]struct{}, len(*values))
	for _, value := range *values {
		if err := validateText("build tag", value); err != nil {
			return err
		}
		if !buildTagPattern.MatchString(value) {
			return fmt.Errorf("invalid build tag %q", value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("duplicate build tag %q", value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func isModuleMode(mode ModuleMode) bool {
	return mode == ModuleModeReadonly || mode == ModuleModeVendor || mode == ModuleModeMod
}

func decodeStrictYAML(reader io.Reader, destination any) error {
	if reader == nil {
		return errors.New("configuration reader is nil")
	}

	decoder := yaml.NewDecoder(reader)
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty configuration")
		}
		return fmt.Errorf("decode configuration: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("configuration contains multiple YAML documents")
		}
		return fmt.Errorf("decode trailing configuration document: %w", err)
	}

	encoded, err := yaml.Marshal(&node)
	if err != nil {
		return fmt.Errorf("encode configuration node: %w", err)
	}
	strictDecoder := yaml.NewDecoder(bytes.NewReader(encoded))
	strictDecoder.KnownFields(true)
	if err := strictDecoder.Decode(destination); err != nil {
		return fmt.Errorf("decode configuration: %w", err)
	}
	return nil
}

func isProfile(profile Profile) bool {
	return profile == ProfileGoStrict || profile == ProfileGoLibrary || profile == ProfileRepositoryOnly
}

func validateText(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}
