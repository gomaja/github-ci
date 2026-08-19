package goexecution

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gomaja/github-ci/internal/config"
)

// Tool identifies one supported Go execution command.
type Tool string

const (
	// ToolBuild compiles configured packages.
	ToolBuild Tool = "build"
	// ToolTest runs configured packages with coverage.
	ToolTest Tool = "test"
	// ToolRace runs configured packages with the race detector.
	ToolRace Tool = "race"
	// ToolVet runs go vet over configured packages.
	ToolVet Tool = "vet"
	// ToolGopls checks the separately supplied tracked Go files.
	ToolGopls Tool = "gopls"
	// ToolStaticcheck runs Staticcheck over configured packages.
	ToolStaticcheck Tool = "staticcheck"
	// ToolGolangCILint runs golangci-lint over configured packages.
	ToolGolangCILint Tool = "golangci-lint"
	// ToolGovulncheck scans configured packages for reachable vulnerabilities.
	ToolGovulncheck Tool = "govulncheck"
)

var tools = []Tool{
	ToolBuild,
	ToolTest,
	ToolRace,
	ToolVet,
	ToolGopls,
	ToolStaticcheck,
	ToolGolangCILint,
	ToolGovulncheck,
}

// Invocation contains environment entries and an executable argument array.
type Invocation struct {
	Environment []string `json:"environment"`
	Arguments   []string `json:"arguments"`
}

// InvocationFor translates a resolved module policy into one exact command.
func InvocationFor(module ModulePlan, tool Tool) (Invocation, error) {
	mode := string(module.ModuleMode)
	if mode != string(config.ModuleModeReadonly) && mode != string(config.ModuleModeVendor) && mode != string(config.ModuleModeMod) {
		return Invocation{}, fmt.Errorf("unsupported module mode %q", module.ModuleMode)
	}
	if len(module.Packages) == 0 {
		return Invocation{}, fmt.Errorf("module %q has no package scope", module.Path)
	}
	if module.PackageParallelism < 1 {
		return Invocation{}, fmt.Errorf("module %q has invalid package parallelism", module.Path)
	}
	if module.RaceParallelism < 1 {
		return Invocation{}, fmt.Errorf("module %q has invalid race parallelism", module.Path)
	}

	tags := strings.Join(module.BuildTags, ",")
	packages := clone(module.Packages)
	switch tool {
	case ToolBuild:
		arguments := goArguments("build", mode, module.PackageParallelism, tags)
		return invocation(arguments, packages), nil
	case ToolTest:
		arguments := goArguments("test", mode, module.PackageParallelism, tags)
		arguments = append(arguments, "-timeout="+module.TestTimeout, "-count=1", "-covermode=atomic")
		if module.CoveragePackagesSet && len(module.CoveragePackages) != 0 {
			arguments = append(arguments, "-coverpkg="+strings.Join(module.CoveragePackages, ","))
		}
		return invocation(arguments, packages), nil
	case ToolRace:
		arguments := []string{
			"go", "test", "-mod=" + mode,
			"-p=" + strconv.Itoa(module.RaceParallelism),
			"-parallel=" + strconv.Itoa(module.RaceParallelism),
		}
		arguments = appendTags(arguments, tags, "-tags=")
		arguments = append(arguments, "-timeout="+module.TestTimeout, "-count=1", "-race")
		return invocation(arguments, packages), nil
	case ToolVet:
		arguments := goArguments("vet", mode, module.PackageParallelism, tags)
		return invocation(arguments, packages), nil
	case ToolGopls:
		goFlags := "GOFLAGS=-mod=" + mode
		if tags != "" {
			goFlags += " -tags=" + tags
		}
		return Invocation{
			Environment: []string{goFlags, "GOMAXPROCS=" + strconv.Itoa(module.PackageParallelism)},
			Arguments:   []string{"gopls", "check"},
		}, nil
	case ToolStaticcheck:
		arguments := []string{"staticcheck"}
		arguments = appendTags(arguments, tags, "-tags=")
		return Invocation{
			Environment: toolEnvironment(mode, module.PackageParallelism),
			Arguments:   append(arguments, packages...),
		}, nil
	case ToolGolangCILint:
		arguments := []string{
			"golangci-lint", "run", "--modules-download-mode", mode,
			"--concurrency", strconv.Itoa(module.PackageParallelism),
		}
		arguments = appendTags(arguments, tags, "--build-tags", "")
		return invocation(arguments, packages), nil
	case ToolGovulncheck:
		arguments := []string{"govulncheck"}
		arguments = appendTags(arguments, tags, "-tags", "")
		return Invocation{
			Environment: toolEnvironment(mode, module.PackageParallelism),
			Arguments:   append(arguments, packages...),
		}, nil
	default:
		return Invocation{}, fmt.Errorf("unsupported Go execution tool %q", tool)
	}
}

func goArguments(command, mode string, parallelism int, tags string) []string {
	arguments := []string{"go", command, "-mod=" + mode, "-p=" + strconv.Itoa(parallelism)}
	return appendTags(arguments, tags, "-tags=")
}

func appendTags(arguments []string, tags string, flag ...string) []string {
	if tags == "" {
		return arguments
	}
	if len(flag) == 2 {
		return append(arguments, flag[0], tags)
	}
	return append(arguments, flag[0]+tags)
}

func invocation(arguments, packages []string) Invocation {
	return Invocation{Environment: []string{}, Arguments: append(arguments, packages...)}
}

func toolEnvironment(mode string, parallelism int) []string {
	return []string{"GOFLAGS=-mod=" + mode, "GOMAXPROCS=" + strconv.Itoa(parallelism)}
}
