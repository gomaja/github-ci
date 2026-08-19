// Package goexecution resolves validated consumer settings into deterministic
// per-module Go command plans.
package goexecution

import (
	"errors"
	"fmt"
	"slices"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/pathpolicy"
)

// SchemaVersion identifies the serialized Go execution plan contract.
const SchemaVersion = "1"

// ModulePlan is the complete, immutable execution policy for one Go module.
type ModulePlan struct {
	Path                string              `json:"path"`
	Directory           string              `json:"directory"`
	Packages            []string            `json:"packages"`
	ModuleMode          config.ModuleMode   `json:"module_mode"`
	BuildTags           []string            `json:"build_tags"`
	TestTimeout         string              `json:"test_timeout"`
	PackageParallelism  int                 `json:"package_parallelism"`
	RaceParallelism     int                 `json:"race_parallelism"`
	CoveragePackages    []string            `json:"coverage_packages"`
	CoveragePackagesSet bool                `json:"coverage_packages_set"`
	Invocations         map[Tool]Invocation `json:"invocations"`
}

// Plan contains the sorted execution policy for every tracked Go module.
type Plan struct {
	SchemaVersion string       `json:"schema_version"`
	Modules       []ModulePlan `json:"modules"`
}

// Resolve applies built-in defaults, consumer defaults, and per-module
// replacements to an exact set of tracked Go modules.
func Resolve(consumer config.Consumer, tracked []string) (Plan, error) {
	if err := consumer.Validate(); err != nil {
		return Plan{}, fmt.Errorf("consumer configuration: %w", err)
	}
	if consumer.Profile == config.ProfileRepositoryOnly {
		return Plan{}, errors.New("repository-only profile does not produce a Go execution plan")
	}
	modules, err := validateTrackedModules(tracked)
	if err != nil {
		return Plan{}, err
	}
	if len(modules) == 0 {
		return Plan{}, fmt.Errorf("profile %q requires at least one tracked module", consumer.Profile)
	}

	settings := builtInSettings()
	configured := map[string]config.GoSettings{}
	if consumer.Go != nil {
		settings = apply(settings, consumer.Go.Defaults)
		for _, module := range consumer.Go.Modules {
			configured[string(module.Path)] = module.GoSettings
		}
	}
	if len(configured) != 0 {
		for module := range configured {
			if !slices.Contains(modules, module) {
				return Plan{}, fmt.Errorf("configured module %q has no tracked go.mod", module)
			}
		}
		for _, module := range modules {
			if _, exists := configured[module]; !exists {
				return Plan{}, fmt.Errorf("configuration omits tracked module %q", module)
			}
		}
	}

	plan := Plan{SchemaVersion: SchemaVersion, Modules: make([]ModulePlan, 0, len(modules))}
	for _, module := range modules {
		resolved := settings
		if overrides, exists := configured[module]; exists {
			resolved = apply(resolved, overrides)
		}
		resolved.Path = module
		resolved.Directory = module
		resolved.Packages = clone(resolved.Packages)
		resolved.BuildTags = clone(resolved.BuildTags)
		resolved.CoveragePackages = clone(resolved.CoveragePackages)
		resolved.Invocations = make(map[Tool]Invocation, len(tools))
		for _, tool := range tools {
			invocation, invocationErr := InvocationFor(resolved, tool)
			if invocationErr != nil {
				return Plan{}, invocationErr
			}
			resolved.Invocations[tool] = invocation
		}
		plan.Modules = append(plan.Modules, resolved)
	}
	return plan, nil
}

func validateTrackedModules(tracked []string) ([]string, error) {
	modules := slices.Clone(tracked)
	slices.Sort(modules)
	for index, module := range modules {
		if err := pathpolicy.Validate("tracked module", module); err != nil {
			return nil, err
		}
		if index != 0 && modules[index-1] == module {
			return nil, fmt.Errorf("duplicate tracked module %q", module)
		}
	}
	return modules, nil
}

func builtInSettings() ModulePlan {
	return ModulePlan{
		Packages:            []string{"./..."},
		ModuleMode:          config.ModuleModeReadonly,
		BuildTags:           []string{},
		TestTimeout:         "10m",
		PackageParallelism:  4,
		RaceParallelism:     1,
		CoveragePackages:    []string{"./..."},
		CoveragePackagesSet: true,
	}
}

func apply(base ModulePlan, settings config.GoSettings) ModulePlan {
	if settings.Packages != nil {
		base.Packages = *settings.Packages
	}
	if settings.ModuleMode != nil {
		base.ModuleMode = *settings.ModuleMode
	}
	if settings.BuildTags != nil {
		base.BuildTags = *settings.BuildTags
	}
	if settings.TestTimeout != nil {
		base.TestTimeout = *settings.TestTimeout
	}
	if settings.PackageParallelism != nil {
		base.PackageParallelism = *settings.PackageParallelism
	}
	if settings.RaceParallelism != nil {
		base.RaceParallelism = *settings.RaceParallelism
	}
	if settings.CoveragePackages != nil {
		base.CoveragePackages = *settings.CoveragePackages
		base.CoveragePackagesSet = true
	}
	return base
}

func clone(values []string) []string {
	return append([]string{}, values...)
}
