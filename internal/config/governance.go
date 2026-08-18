package config

import (
	"fmt"
	"io"
	"regexp"
)

const githubAPIVersion = "2026-03-10"

var workflowSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

var (
	githubOwnerPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	githubRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
)

// Governance is the desired state for a set of public GitHub repositories.
type Governance struct {
	SchemaVersion int                `yaml:"schema-version"`
	APIVersion    string             `yaml:"api-version"`
	Owners        []Owner            `yaml:"owners"`
	Defaults      GovernanceDefaults `yaml:"defaults"`
	Repositories  []Repository       `yaml:"repositories"`
}

// Owner is a GitHub account permitted to own a governed repository.
type Owner struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
}

// GovernanceDefaults is the policy shared by all governed repositories.
type GovernanceDefaults struct {
	Profile                Profile `yaml:"profile"`
	DefaultBranch          string  `yaml:"default-branch"`
	RequiredCheck          string  `yaml:"required-check"`
	PublicOnly             bool    `yaml:"public-only"`
	RefuseForks            bool    `yaml:"refuse-forks"`
	RefuseArchived         bool    `yaml:"refuse-archived"`
	RefusePrivate          bool    `yaml:"refuse-private"`
	RefuseUnexpectedOwners bool    `yaml:"refuse-unexpected-owners"`
}

// Repository adds repository-specific applicability and caller policy.
type Repository struct {
	Name                  string    `yaml:"name"`
	Owner                 string    `yaml:"owner,omitempty"`
	Profile               Profile   `yaml:"profile,omitempty"`
	Modules               []Module  `yaml:"modules,omitempty"`
	BuildTags             []string  `yaml:"build-tags,omitempty"`
	Services              []Service `yaml:"services,omitempty"`
	Generated             []string  `yaml:"generated,omitempty"`
	Exceptions            string    `yaml:"exceptions,omitempty"`
	EnforceCaller         bool      `yaml:"enforce-caller"`
	WorkflowSHA           string    `yaml:"workflow-sha,omitempty"`
	ObservedRequiredCheck string    `yaml:"observed-required-check,omitempty"`
}

// DecodeGovernance parses and validates exactly one strict YAML document.
func DecodeGovernance(reader io.Reader) (Governance, error) {
	var governance Governance
	if err := decodeStrictYAML(reader, &governance); err != nil {
		return Governance{}, err
	}
	if err := governance.Validate(); err != nil {
		return Governance{}, err
	}
	return governance, nil
}

// Validate verifies the semantic constraints of a governance manifest.
func (governance Governance) Validate() error {
	if governance.SchemaVersion != schemaVersion {
		return fmt.Errorf("schema-version must be %d", schemaVersion)
	}
	if governance.APIVersion != githubAPIVersion {
		return fmt.Errorf("api-version must be %q", githubAPIVersion)
	}
	if err := governance.Defaults.validate(); err != nil {
		return err
	}

	owners := make(map[string]struct{}, len(governance.Owners))
	for _, owner := range governance.Owners {
		if err := validateText("owner name", owner.Name); err != nil {
			return err
		}
		if !githubOwnerPattern.MatchString(owner.Name) {
			return fmt.Errorf("invalid GitHub owner name %q", owner.Name)
		}
		if owner.Type != "user" && owner.Type != "organization" {
			return fmt.Errorf("unsupported owner type %q", owner.Type)
		}
		if _, exists := owners[owner.Name]; exists {
			return fmt.Errorf("duplicate owner %q", owner.Name)
		}
		owners[owner.Name] = struct{}{}
	}
	if len(owners) == 0 {
		return fmt.Errorf("at least one owner is required")
	}

	repositories := make(map[string]struct{}, len(governance.Repositories))
	for _, repository := range governance.Repositories {
		if err := repository.validate(governance.Defaults.Profile, owners); err != nil {
			return err
		}
		if _, exists := repositories[repository.Name]; exists {
			return fmt.Errorf("duplicate repository %q", repository.Name)
		}
		repositories[repository.Name] = struct{}{}
	}
	if len(repositories) == 0 {
		return fmt.Errorf("at least one repository is required")
	}
	return nil
}

func (defaults GovernanceDefaults) validate() error {
	if !isProfile(defaults.Profile) {
		return fmt.Errorf("unsupported profile %q", defaults.Profile)
	}
	if err := validateText("default-branch", defaults.DefaultBranch); err != nil {
		return err
	}
	if err := validateText("required-check", defaults.RequiredCheck); err != nil {
		return err
	}
	if !defaults.PublicOnly {
		return fmt.Errorf("public-only must be true")
	}
	if !defaults.RefuseForks {
		return fmt.Errorf("refuse-forks must be true")
	}
	if !defaults.RefuseArchived {
		return fmt.Errorf("refuse-archived must be true")
	}
	if !defaults.RefusePrivate {
		return fmt.Errorf("refuse-private must be true")
	}
	if !defaults.RefuseUnexpectedOwners {
		return fmt.Errorf("refuse-unexpected-owners must be true")
	}
	return nil
}

func (repository Repository) validate(defaultProfile Profile, owners map[string]struct{}) error {
	if err := validateText("repository name", repository.Name); err != nil {
		return err
	}
	if !githubRepositoryPattern.MatchString(repository.Name) || repository.Name == "." || repository.Name == ".." {
		return fmt.Errorf("invalid GitHub repository name %q", repository.Name)
	}
	if repository.Owner != "" {
		if err := validateText("repository owner", repository.Owner); err != nil {
			return err
		}
		if _, exists := owners[repository.Owner]; !exists {
			return fmt.Errorf("unexpected owner %q for repository %q", repository.Owner, repository.Name)
		}
	}

	profile := repository.Profile
	if profile == "" {
		profile = defaultProfile
	}
	consumer := Consumer{
		SchemaVersion: schemaVersion,
		Profile:       profile,
		Modules:       repository.Modules,
		BuildTags:     repository.BuildTags,
		Services:      repository.Services,
		Generated:     repository.Generated,
		Exceptions:    repository.Exceptions,
	}
	if err := consumer.Validate(); err != nil {
		return fmt.Errorf("repository %q: %w", repository.Name, err)
	}

	if repository.WorkflowSHA != "" && !workflowSHAPattern.MatchString(repository.WorkflowSHA) {
		return fmt.Errorf("repository %q workflow-sha must be an immutable 40-character lowercase hexadecimal commit SHA", repository.Name)
	}
	if repository.ObservedRequiredCheck != "" {
		if err := validateText("observed-required-check", repository.ObservedRequiredCheck); err != nil {
			return fmt.Errorf("repository %q: %w", repository.Name, err)
		}
	}
	if repository.EnforceCaller {
		if repository.WorkflowSHA == "" {
			return fmt.Errorf("repository %q workflow-sha must be an immutable 40-character lowercase hexadecimal commit SHA", repository.Name)
		}
		if repository.ObservedRequiredCheck == "" {
			return fmt.Errorf("repository %q: observed-required-check must not be empty", repository.Name)
		}
	}
	return nil
}
