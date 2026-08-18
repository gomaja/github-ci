// Package applicability detects the assurance policy required by tracked files.
package applicability

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/pathpolicy"
)

// Capability is a tracked-file condition that activates an analyzer command.
type Capability string

const (
	CapabilityAlways     Capability = "always"
	CapabilityGo         Capability = "go"
	CapabilityOrdinaryGo Capability = "ordinary-go"
	CapabilityShell      Capability = "shell"
	CapabilityDocker     Capability = "docker"
	CapabilityWorkflow   Capability = "workflow"
	CapabilityTerraform  Capability = "terraform"
	CapabilityMarkdown   Capability = "markdown"
	CapabilityYAML       Capability = "yaml"
)

const (
	ReasonNoGoModule        = "no-go-module"
	ReasonNoOrdinaryGoFiles = "no-ordinary-go-files"
	ReasonNoShellFiles      = "no-shell-files"
	ReasonNoDockerfiles     = "no-dockerfiles"
	ReasonNoWorkflows       = "no-github-workflows"
	ReasonNoTerraform       = "no-terraform-files"
	ReasonNoMarkdown        = "no-markdown-files"
	ReasonNoYAML            = "no-yaml-files"
)

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Entry is one immutable analyzer command in the applicability catalog.
type Entry struct {
	Tool          string
	CommandID     string
	ParserVersion string
	Capability    Capability
	ReasonCode    string
	Profiles      []config.Profile
}

// Catalog is the complete set of analyzer commands available to a policy.
type Catalog []Entry

var defaultCatalog = Catalog{
	{Tool: "actionlint", CommandID: "actionlint/workflows", ParserVersion: "sarif/v1", Capability: CapabilityWorkflow, ReasonCode: ReasonNoWorkflows, Profiles: allProfiles()},
	{Tool: "checkov", CommandID: "checkov/infrastructure", ParserVersion: "checkov-json/v1", Capability: CapabilityTerraform, ReasonCode: ReasonNoTerraform, Profiles: allProfiles()},
	{Tool: "codeql", CommandID: "codeql/actions", ParserVersion: "sarif/v1", Capability: CapabilityWorkflow, ReasonCode: ReasonNoWorkflows, Profiles: allProfiles()},
	{Tool: "codeql", CommandID: "codeql/go", ParserVersion: "sarif/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "dependency-review", CommandID: "dependency-review/changes", ParserVersion: "sarif/v1", Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "gitleaks", CommandID: "gitleaks/content", ParserVersion: "gitleaks-json/v1", Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "go", CommandID: "go/build", ParserVersion: "command-status/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "go", CommandID: "go/module-integrity", ParserVersion: "command-status/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "go", CommandID: "go/race", ParserVersion: "gotestsum-junit/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "go", CommandID: "go/test", ParserVersion: "gotestsum-junit/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "go", CommandID: "go/vet", ParserVersion: "command-status/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "gofmt", CommandID: "gofmt/tracked-go", ParserVersion: "path-list/v1", Capability: CapabilityOrdinaryGo, ReasonCode: ReasonNoOrdinaryGoFiles, Profiles: goProfiles()},
	{Tool: "goimports", CommandID: "goimports/tracked-go", ParserVersion: "path-list/v1", Capability: CapabilityOrdinaryGo, ReasonCode: ReasonNoOrdinaryGoFiles, Profiles: goProfiles()},
	{Tool: "golangci-lint", CommandID: "golangci-lint/default", ParserVersion: "golangci-lint-json/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "gopls", CommandID: "gopls/tracked-go", ParserVersion: "command-status/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "govulncheck", CommandID: "govulncheck/modules", ParserVersion: "govulncheck-json/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "hadolint", CommandID: "hadolint/dockerfiles", ParserVersion: "sarif/v1", Capability: CapabilityDocker, ReasonCode: ReasonNoDockerfiles, Profiles: allProfiles()},
	{Tool: "markdownlint", CommandID: "markdownlint/documents", ParserVersion: "markdownlint-json/v1", Capability: CapabilityMarkdown, ReasonCode: ReasonNoMarkdown, Profiles: allProfiles()},
	{Tool: "osv-scanner", CommandID: "osv-scanner/dependencies", ParserVersion: "osv-json/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "semgrep", CommandID: "semgrep/source", ParserVersion: "semgrep-json/v1", Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "shellcheck", CommandID: "shellcheck/scripts", ParserVersion: "shellcheck-json1/v1", Capability: CapabilityShell, ReasonCode: ReasonNoShellFiles, Profiles: allProfiles()},
	{Tool: "shfmt", CommandID: "shfmt/scripts", ParserVersion: "path-list/v1", Capability: CapabilityShell, ReasonCode: ReasonNoShellFiles, Profiles: allProfiles()},
	{Tool: "staticcheck", CommandID: "staticcheck/default", ParserVersion: "staticcheck-jsonl/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "trivy", CommandID: "trivy/filesystem", ParserVersion: "trivy-json/v1", Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "yamllint", CommandID: "yamllint/documents", ParserVersion: "yamllint-parsable/v1", Capability: CapabilityYAML, ReasonCode: ReasonNoYAML, Profiles: allProfiles()},
	{Tool: "zizmor", CommandID: "zizmor/workflows", ParserVersion: "sarif/v1", Capability: CapabilityWorkflow, ReasonCode: ReasonNoWorkflows, Profiles: allProfiles()},
}

// DefaultCatalog returns an independent copy of the policy catalog.
func DefaultCatalog() Catalog {
	result := slices.Clone(defaultCatalog)
	for index := range result {
		result[index].Profiles = slices.Clone(result[index].Profiles)
	}
	return result
}

// Validate rejects incomplete, duplicate, or contradictory catalog entries.
func (catalog Catalog) Validate() error {
	if len(catalog) == 0 {
		return fmt.Errorf("catalog must contain at least one analyzer command")
	}
	identities := make(map[string]struct{}, len(catalog))
	for index, entry := range catalog {
		if !identifierPattern.MatchString(entry.Tool) {
			return fmt.Errorf("catalog entry %d has invalid tool %q", index, entry.Tool)
		}
		if err := pathpolicy.Validate("command_id", entry.CommandID); err != nil {
			return fmt.Errorf("catalog entry %d: %w", index, err)
		}
		if entry.ParserVersion == "" {
			return fmt.Errorf("catalog entry %d parser version must not be empty", index)
		}
		if !isCapability(entry.Capability) {
			return fmt.Errorf("catalog entry %d has invalid capability %q", index, entry.Capability)
		}
		if entry.Capability == CapabilityAlways && entry.ReasonCode != "" {
			return fmt.Errorf("catalog entry %d always-applicable command must not have a reason code", index)
		}
		if entry.Capability != CapabilityAlways && !IsReasonCode(entry.ReasonCode) {
			return fmt.Errorf("catalog entry %d has invalid reason code %q", index, entry.ReasonCode)
		}
		if len(entry.Profiles) == 0 {
			return fmt.Errorf("catalog entry %d must select at least one profile", index)
		}
		profiles := make(map[config.Profile]struct{}, len(entry.Profiles))
		for _, profile := range entry.Profiles {
			if !isProfile(profile) {
				return fmt.Errorf("catalog entry %d has invalid profile %q", index, profile)
			}
			if _, exists := profiles[profile]; exists {
				return fmt.Errorf("catalog entry %d repeats profile %q", index, profile)
			}
			profiles[profile] = struct{}{}
		}
		identity := entry.Tool + "/" + entry.CommandID
		if _, exists := identities[identity]; exists {
			return fmt.Errorf("duplicate catalog identity %q", identity)
		}
		identities[identity] = struct{}{}
	}
	return nil
}

// HasTool reports whether the catalog contains a command for tool.
func (catalog Catalog) HasTool(tool string) bool {
	return slices.ContainsFunc(catalog, func(entry Entry) bool { return entry.Tool == tool })
}

// IsKnownTool reports whether tool is present in the default policy catalog.
func IsKnownTool(tool string) bool { return defaultCatalog.HasTool(tool) }

// ReasonFor returns the detector-owned N/A reason for one exact command.
func ReasonFor(tool, commandID string) (string, bool) {
	for _, entry := range defaultCatalog {
		if entry.Tool == tool && entry.CommandID == commandID && entry.Capability != CapabilityAlways {
			return entry.ReasonCode, true
		}
	}
	return "", false
}

// IsReasonCode reports whether code is a detector-owned not-applicable reason.
func IsReasonCode(code string) bool {
	switch code {
	case ReasonNoGoModule, ReasonNoOrdinaryGoFiles, ReasonNoShellFiles,
		ReasonNoDockerfiles, ReasonNoWorkflows, ReasonNoTerraform,
		ReasonNoMarkdown, ReasonNoYAML:
		return true
	default:
		return false
	}
}

func isCapability(capability Capability) bool {
	switch capability {
	case CapabilityAlways, CapabilityGo, CapabilityOrdinaryGo, CapabilityShell,
		CapabilityDocker, CapabilityWorkflow, CapabilityTerraform,
		CapabilityMarkdown, CapabilityYAML:
		return true
	default:
		return false
	}
}

func isProfile(profile config.Profile) bool {
	return profile == config.ProfileGoStrict || profile == config.ProfileGoLibrary || profile == config.ProfileRepositoryOnly
}

func allProfiles() []config.Profile {
	return []config.Profile{config.ProfileGoStrict, config.ProfileGoLibrary, config.ProfileRepositoryOnly}
}

func goProfiles() []config.Profile {
	return []config.Profile{config.ProfileGoStrict, config.ProfileGoLibrary}
}
