package goexecution

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/github-ci/internal/config"
)

func TestResolveAppliesBuiltInDefaultsToDiscoveredModules(t *testing.T) {
	consumer := config.Consumer{SchemaVersion: 2, Profile: config.ProfileGoStrict}
	want := Plan{
		SchemaVersion: SchemaVersion,
		Modules: []ModulePlan{
			{
				Path: ".", Directory: ".", Packages: []string{"./..."}, ModuleMode: config.ModuleModeReadonly,
				BuildTags: []string{}, TestTimeout: "10m", PackageParallelism: 4, RaceParallelism: 1,
				CoveragePackages: []string{"./..."}, CoveragePackagesSet: true,
			},
			{
				Path: "tools", Directory: "tools", Packages: []string{"./..."}, ModuleMode: config.ModuleModeReadonly,
				BuildTags: []string{}, TestTimeout: "10m", PackageParallelism: 4, RaceParallelism: 1,
				CoveragePackages: []string{"./..."}, CoveragePackagesSet: true,
			},
		},
	}

	got, err := Resolve(consumer, []string{"tools", "."})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	for index := range got.Modules {
		if len(got.Modules[index].Invocations) != len(tools) {
			t.Fatalf("module %q invocations = %d, want %d", got.Modules[index].Path, len(got.Modules[index].Invocations), len(tools))
		}
		got.Modules[index].Invocations = nil
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve() = %#v, want %#v", got, want)
	}
}

func TestResolveReplacesDefaultsWithPerModuleOverrides(t *testing.T) {
	defaultsPackages := []string{"./..."}
	defaultMode := config.ModuleModeReadonly
	defaultTags := []string{"sqlite", "integration"}
	defaultTimeout := "10m"
	defaultParallel := 4
	defaultRace := 1
	defaultCoverage := []string{"./..."}
	rootPackages := []string{"./cmd/...", "./internal/..."}
	rootMode := config.ModuleModeMod
	rootTags := []string{}
	rootTimeout := "15m"
	rootParallel := 2
	rootRace := 2
	toolsMode := config.ModuleModeVendor
	toolsCoverage := []string{}
	consumer := config.Consumer{
		SchemaVersion: 2,
		Profile:       config.ProfileGoLibrary,
		Go: &config.Go{
			Defaults: config.GoSettings{
				Packages: &defaultsPackages, ModuleMode: &defaultMode, BuildTags: &defaultTags,
				TestTimeout: &defaultTimeout, PackageParallelism: &defaultParallel,
				RaceParallelism: &defaultRace, CoveragePackages: &defaultCoverage,
			},
			Modules: []config.GoModule{
				{Path: ".", GoSettings: config.GoSettings{
					Packages: &rootPackages, ModuleMode: &rootMode, BuildTags: &rootTags,
					TestTimeout: &rootTimeout, PackageParallelism: &rootParallel, RaceParallelism: &rootRace,
				}},
				{Path: "tools", GoSettings: config.GoSettings{ModuleMode: &toolsMode, CoveragePackages: &toolsCoverage}},
			},
		},
	}

	plan, err := Resolve(consumer, []string{".", "tools"})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	root := plan.Modules[0]
	if got := strings.Join(root.Packages, ","); got != "./cmd/...,./internal/..." {
		t.Fatalf("root packages = %q", got)
	}
	if root.ModuleMode != config.ModuleModeMod || len(root.BuildTags) != 0 || root.TestTimeout != "15m" || root.PackageParallelism != 2 || root.RaceParallelism != 2 {
		t.Fatalf("root overrides = %#v", root)
	}
	if got := strings.Join(root.CoveragePackages, ","); got != "./..." || !root.CoveragePackagesSet {
		t.Fatalf("root coverage = %#v", root)
	}
	tools := plan.Modules[1]
	if tools.ModuleMode != config.ModuleModeVendor || tools.CoveragePackages == nil || len(tools.CoveragePackages) != 0 || !tools.CoveragePackagesSet {
		t.Fatalf("tools overrides = %#v", tools)
	}
	if got := strings.Join(tools.BuildTags, ","); got != "sqlite,integration" {
		t.Fatalf("tools inherited build tags = %q", got)
	}
}

func TestResolveRejectsModuleSetMismatches(t *testing.T) {
	tests := []struct {
		name     string
		consumer config.Consumer
		tracked  []string
		want     string
	}{
		{name: "no tracked module", consumer: configuredConsumer("."), tracked: nil, want: "requires at least one tracked module"},
		{name: "duplicate tracked module", consumer: configuredConsumer("."), tracked: []string{".", "."}, want: "duplicate tracked module"},
		{name: "configured module missing", consumer: configuredConsumer(".", "tools"), tracked: []string{"."}, want: "configured module \"tools\" has no tracked go.mod"},
		{name: "tracked module omitted", consumer: configuredConsumer("."), tracked: []string{".", "tools"}, want: "configuration omits tracked module \"tools\""},
		{name: "repository-only", consumer: config.Consumer{SchemaVersion: 2, Profile: config.ProfileRepositoryOnly}, tracked: []string{"."}, want: "does not produce a Go execution plan"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Resolve(test.consumer, test.tracked)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Resolve() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestResolveDoesNotAliasConfigurationSlices(t *testing.T) {
	packages := []string{"./cmd/..."}
	tags := []string{"sqlite"}
	coverage := []string{"./internal/..."}
	consumer := config.Consumer{
		SchemaVersion: 2,
		Profile:       config.ProfileGoStrict,
		Go: &config.Go{Defaults: config.GoSettings{
			Packages: &packages, BuildTags: &tags, CoveragePackages: &coverage,
		}},
	}
	plan, err := Resolve(consumer, []string{"."})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	packages[0] = "./changed/..."
	tags[0] = "changed"
	coverage[0] = "./changed/..."
	if got := strings.Join(plan.Modules[0].Packages, ","); got != "./cmd/..." {
		t.Fatalf("plan packages changed through input alias: %q", got)
	}
	if got := strings.Join(plan.Modules[0].BuildTags, ","); got != "sqlite" {
		t.Fatalf("plan tags changed through input alias: %q", got)
	}
	if got := strings.Join(plan.Modules[0].CoveragePackages, ","); got != "./internal/..." {
		t.Fatalf("plan coverage changed through input alias: %q", got)
	}
}

func configuredConsumer(modules ...string) config.Consumer {
	configured := make([]config.GoModule, len(modules))
	for index, module := range modules {
		configured[index].Path = config.Module(module)
	}
	return config.Consumer{SchemaVersion: 2, Profile: config.ProfileGoStrict, Go: &config.Go{Modules: configured}}
}
