package goexecution

import (
	"reflect"
	"testing"

	"github.com/gomaja/github-ci/internal/config"
)

func TestInvocationForAppliesEveryModuleControl(t *testing.T) {
	module := invocationModule()
	tests := []struct {
		tool Tool
		want Invocation
	}{
		{
			tool: ToolBuild,
			want: Invocation{Environment: []string{}, Arguments: []string{
				"go", "build", "-mod=vendor", "-p=3", "-tags=sqlite,integration", "./cmd/...", "./internal/...",
			}},
		},
		{
			tool: ToolTest,
			want: Invocation{Environment: []string{}, Arguments: []string{
				"go", "test", "-mod=vendor", "-p=3", "-tags=sqlite,integration", "-timeout=12m", "-count=1", "-covermode=atomic",
				"-coverpkg=./cmd/...,./internal/...", "./cmd/...", "./internal/...",
			}},
		},
		{
			tool: ToolRace,
			want: Invocation{Environment: []string{}, Arguments: []string{
				"go", "test", "-mod=vendor", "-p=2", "-parallel=2", "-tags=sqlite,integration", "-timeout=12m", "-count=1", "-race",
				"./cmd/...", "./internal/...",
			}},
		},
		{
			tool: ToolVet,
			want: Invocation{Environment: []string{}, Arguments: []string{
				"go", "vet", "-mod=vendor", "-p=3", "-tags=sqlite,integration", "./cmd/...", "./internal/...",
			}},
		},
		{
			tool: ToolGopls,
			want: Invocation{Environment: []string{"GOFLAGS=-mod=vendor -tags=sqlite,integration", "GOMAXPROCS=3"}, Arguments: []string{
				"gopls", "check",
			}},
		},
		{
			tool: ToolStaticcheck,
			want: Invocation{Environment: []string{"GOFLAGS=-mod=vendor", "GOMAXPROCS=3"}, Arguments: []string{
				"staticcheck", "-f=json", "-tags=sqlite,integration", "./cmd/...", "./internal/...",
			}},
		},
		{
			tool: ToolGolangCILint,
			want: Invocation{Environment: []string{}, Arguments: []string{
				"golangci-lint", "run", "--modules-download-mode", "vendor", "--concurrency", "3", "--build-tags", "sqlite,integration",
				"./cmd/...", "./internal/...",
			}},
		},
		{
			tool: ToolGovulncheck,
			want: Invocation{Environment: []string{"GOFLAGS=-mod=vendor", "GOMAXPROCS=3"}, Arguments: []string{
				"govulncheck", "-json", "-tags", "sqlite,integration", "./cmd/...", "./internal/...",
			}},
		},
	}

	for _, test := range tests {
		t.Run(string(test.tool), func(t *testing.T) {
			got, err := InvocationFor(module, test.tool)
			if err != nil {
				t.Fatalf("InvocationFor() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("InvocationFor() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestInvocationForOmitsEmptyTagsAndCoverageScope(t *testing.T) {
	module := invocationModule()
	module.ModuleMode = config.ModuleModeReadonly
	module.BuildTags = []string{}
	module.CoveragePackages = []string{}
	module.CoveragePackagesSet = true

	testInvocation, err := InvocationFor(module, ToolTest)
	if err != nil {
		t.Fatalf("InvocationFor(test) error = %v", err)
	}
	wantTest := []string{
		"go", "test", "-mod=readonly", "-p=3", "-timeout=12m", "-count=1", "-covermode=atomic", "./cmd/...", "./internal/...",
	}
	if !reflect.DeepEqual(testInvocation.Arguments, wantTest) {
		t.Fatalf("test arguments = %#v, want %#v", testInvocation.Arguments, wantTest)
	}

	goplsInvocation, err := InvocationFor(module, ToolGopls)
	if err != nil {
		t.Fatalf("InvocationFor(gopls) error = %v", err)
	}
	if want := []string{"GOFLAGS=-mod=readonly", "GOMAXPROCS=3"}; !reflect.DeepEqual(goplsInvocation.Environment, want) {
		t.Fatalf("gopls environment = %#v, want %#v", goplsInvocation.Environment, want)
	}
}

func TestInvocationForSupportsEveryModuleMode(t *testing.T) {
	for _, mode := range []config.ModuleMode{config.ModuleModeReadonly, config.ModuleModeVendor, config.ModuleModeMod} {
		t.Run(string(mode), func(t *testing.T) {
			module := invocationModule()
			module.ModuleMode = mode
			got, err := InvocationFor(module, ToolBuild)
			if err != nil {
				t.Fatalf("InvocationFor() error = %v", err)
			}
			if got.Arguments[2] != "-mod="+string(mode) {
				t.Fatalf("module flag = %q", got.Arguments[2])
			}
		})
	}
}

func TestInvocationForRejectsUnknownTool(t *testing.T) {
	_, err := InvocationFor(invocationModule(), Tool("unknown"))
	if err == nil || err.Error() != `unsupported Go execution tool "unknown"` {
		t.Fatalf("InvocationFor() error = %v", err)
	}
}

func invocationModule() ModulePlan {
	return ModulePlan{
		Path: ".", Directory: ".", Packages: []string{"./cmd/...", "./internal/..."}, ModuleMode: config.ModuleModeVendor,
		BuildTags: []string{"sqlite", "integration"}, TestTimeout: "12m", PackageParallelism: 3, RaceParallelism: 2,
		CoveragePackages: []string{"./cmd/...", "./internal/..."}, CoveragePackagesSet: true,
	}
}
