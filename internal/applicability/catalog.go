// Package applicability detects the assurance policy required by tracked files.
package applicability

import (
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/pathpolicy"
)

// Capability is a tracked-file condition that activates an analyzer command.
type Capability string

const (
	parserCommandStatus = "command-status/v1"
	parserPathList      = "path-list/v1"
	parserSARIF         = "sarif/v1"
)

const (
	// CapabilityAlways and the following values identify tracked-file capabilities.
	CapabilityAlways Capability = "always"
	// CapabilityGo activates analyzers for repositories containing a Go module.
	CapabilityGo Capability = "go"
	// CapabilityOrdinaryGo activates analyzers for non-generated Go source.
	CapabilityOrdinaryGo Capability = "ordinary-go"
	// CapabilityShell activates analyzers for shell scripts.
	CapabilityShell Capability = "shell"
	// CapabilityDocker activates analyzers for Dockerfiles.
	CapabilityDocker Capability = "docker"
	// CapabilityWorkflow activates analyzers for GitHub Actions workflows.
	CapabilityWorkflow Capability = "workflow"
	// CapabilityTerraform activates analyzers for Terraform files.
	CapabilityTerraform Capability = "terraform"
	// CapabilityMarkdown activates analyzers for Markdown files.
	CapabilityMarkdown Capability = "markdown"
	// CapabilityYAML activates analyzers for YAML files.
	CapabilityYAML Capability = "yaml"
	// CapabilityJSON activates analyzers for JSON files.
	CapabilityJSON Capability = "json"
)

const (
	// ReasonNoGoModule and the following values explain why a capability is absent.
	ReasonNoGoModule = "no-go-module"
	// ReasonNoOrdinaryGoFiles means only generated Go files were detected.
	ReasonNoOrdinaryGoFiles = "no-ordinary-go-files"
	// ReasonNoShellFiles means no tracked shell script was detected.
	ReasonNoShellFiles = "no-shell-files"
	// ReasonNoDockerfiles means no tracked Dockerfile was detected.
	ReasonNoDockerfiles = "no-dockerfiles"
	// ReasonNoWorkflows means no tracked GitHub Actions workflow was detected.
	ReasonNoWorkflows = "no-github-workflows"
	// ReasonNoTerraform means no tracked Terraform file was detected.
	ReasonNoTerraform = "no-terraform-files"
	// ReasonNoMarkdown means no tracked Markdown file was detected.
	ReasonNoMarkdown = "no-markdown-files"
	// ReasonNoYAML means no tracked YAML file was detected.
	ReasonNoYAML = "no-yaml-files"
	// ReasonNoJSON means no tracked JSON file was detected.
	ReasonNoJSON = "no-json-files"
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
	{Tool: "actionlint", CommandID: "actionlint/workflows", ParserVersion: "actionlint-json/v1", Capability: CapabilityWorkflow, ReasonCode: ReasonNoWorkflows, Profiles: allProfiles()},
	{Tool: "apidiff", CommandID: "apidiff/public-api", ParserVersion: parserPathList, Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "bash", CommandID: "bash/scripts", ParserVersion: parserPathList, Capability: CapabilityShell, ReasonCode: ReasonNoShellFiles, Profiles: allProfiles()},
	{Tool: "checkov", CommandID: "checkov/infrastructure", ParserVersion: "checkov-json/v1", Capability: CapabilityTerraform, ReasonCode: ReasonNoTerraform, Profiles: allProfiles()},
	{Tool: "codeql", CommandID: "codeql/actions", ParserVersion: parserSARIF, Capability: CapabilityWorkflow, ReasonCode: ReasonNoWorkflows, Profiles: allProfiles()},
	{Tool: "codeql", CommandID: "codeql/go", ParserVersion: parserSARIF, Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "dependency-review", CommandID: "dependency-review/changes", ParserVersion: parserCommandStatus, Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "gitleaks", CommandID: "gitleaks/content", ParserVersion: "gitleaks-json/v1", Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "generated", CommandID: "generated/files", ParserVersion: parserPathList, Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "go", CommandID: "go/build", ParserVersion: parserCommandStatus, Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "go", CommandID: "go/module-integrity", ParserVersion: parserCommandStatus, Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "go", CommandID: "go/race", ParserVersion: "gotestsum-junit/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "go", CommandID: "go/test", ParserVersion: "gotestsum-junit/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "go", CommandID: "go/vet", ParserVersion: parserCommandStatus, Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "gofmt", CommandID: "gofmt/tracked-go", ParserVersion: parserPathList, Capability: CapabilityOrdinaryGo, ReasonCode: ReasonNoOrdinaryGoFiles, Profiles: goProfiles()},
	{Tool: "goimports", CommandID: "goimports/tracked-go", ParserVersion: parserPathList, Capability: CapabilityOrdinaryGo, ReasonCode: ReasonNoOrdinaryGoFiles, Profiles: goProfiles()},
	{Tool: "golangci-lint", CommandID: "golangci-lint/default", ParserVersion: "golangci-lint-json/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "gopls", CommandID: "gopls/tracked-go", ParserVersion: "gopls-diagnostics/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "govulncheck", CommandID: "govulncheck/modules", ParserVersion: "govulncheck-json/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "grype", CommandID: "grype/sbom", ParserVersion: "grype-json/v1", Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "hadolint", CommandID: "hadolint/dockerfiles", ParserVersion: parserSARIF, Capability: CapabilityDocker, ReasonCode: ReasonNoDockerfiles, Profiles: allProfiles()},
	{Tool: "json", CommandID: "json/documents", ParserVersion: parserPathList, Capability: CapabilityJSON, ReasonCode: ReasonNoJSON, Profiles: allProfiles()},
	{Tool: "license", CommandID: "license/dependencies", ParserVersion: "license-inventory/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "markdownlint", CommandID: "markdownlint/documents", ParserVersion: parserPathList, Capability: CapabilityMarkdown, ReasonCode: ReasonNoMarkdown, Profiles: allProfiles()},
	{Tool: "osv-scanner", CommandID: "osv-scanner/dependencies", ParserVersion: "osv-json/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "repository", CommandID: "repository/hygiene", ParserVersion: parserPathList, Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "scorecard", CommandID: "scorecard/repository", ParserVersion: parserSARIF, Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "semgrep", CommandID: "semgrep/source", ParserVersion: "semgrep-json/v1", Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "shellcheck", CommandID: "shellcheck/scripts", ParserVersion: "shellcheck-json/v1", Capability: CapabilityShell, ReasonCode: ReasonNoShellFiles, Profiles: allProfiles()},
	{Tool: "shfmt", CommandID: "shfmt/scripts", ParserVersion: parserPathList, Capability: CapabilityShell, ReasonCode: ReasonNoShellFiles, Profiles: allProfiles()},
	{Tool: "staticcheck", CommandID: "staticcheck/default", ParserVersion: "staticcheck-jsonl/v1", Capability: CapabilityGo, ReasonCode: ReasonNoGoModule, Profiles: goProfiles()},
	{Tool: "syft", CommandID: "syft/sbom", ParserVersion: "spdx-json/v1", Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "trivy", CommandID: "trivy/filesystem", ParserVersion: "trivy-json/v1", Capability: CapabilityAlways, Profiles: allProfiles()},
	{Tool: "yamllint", CommandID: "yamllint/documents", ParserVersion: "yamllint-parsable/v1", Capability: CapabilityYAML, ReasonCode: ReasonNoYAML, Profiles: allProfiles()},
	{Tool: "zizmor", CommandID: "zizmor/workflows", ParserVersion: parserSARIF, Capability: CapabilityWorkflow, ReasonCode: ReasonNoWorkflows, Profiles: allProfiles()},
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
		return errors.New("catalog must contain at least one analyzer command")
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

func (catalog Catalog) validateDefaultPolicy() error {
	if len(catalog) != len(defaultCatalog) {
		return fmt.Errorf("catalog policy drift: got %d commands, want %d", len(catalog), len(defaultCatalog))
	}
	want := make(map[string]Entry, len(defaultCatalog))
	for _, entry := range defaultCatalog {
		want[entry.Tool+"/"+entry.CommandID] = entry
	}
	for _, entry := range catalog {
		identity := entry.Tool + "/" + entry.CommandID
		expected, exists := want[identity]
		if !exists || entry.ParserVersion != expected.ParserVersion || entry.Capability != expected.Capability || entry.ReasonCode != expected.ReasonCode || !sameProfiles(entry.Profiles, expected.Profiles) {
			return fmt.Errorf("catalog policy drift at %q", identity)
		}
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
		ReasonNoMarkdown, ReasonNoYAML, ReasonNoJSON:
		return true
	default:
		return false
	}
}

func isCapability(capability Capability) bool {
	switch capability {
	case CapabilityAlways, CapabilityGo, CapabilityOrdinaryGo, CapabilityShell,
		CapabilityDocker, CapabilityWorkflow, CapabilityTerraform,
		CapabilityMarkdown, CapabilityYAML, CapabilityJSON:
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

func sameProfiles(left, right []config.Profile) bool {
	leftCopy := slices.Clone(left)
	rightCopy := slices.Clone(right)
	slices.Sort(leftCopy)
	slices.Sort(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}
