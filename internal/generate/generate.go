// Package generate validates immutable policy locks and renders committed artifacts.
package generate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

const schemaVersion = 1

var (
	actionSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	idPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	checksumPattern  = regexp.MustCompile(`^(?:sha256:[0-9a-f]{64}|sha512:[A-Za-z0-9+/]+={0,2}|h1:[A-Za-z0-9+/]+={0,2})$`)
)

var templatePaths = []string{
	"templates/workflows/go.yml.tmpl",
	"templates/workflows/deep.yml.tmpl",
	"templates/workflows/release.yml.tmpl",
	"templates/callers/github-ci.yml.tmpl",
	"templates/callers/github-ci-deep.yml.tmpl",
	"templates/callers/github-ci-release.yml.tmpl",
	"templates/configs/golangci.yml.tmpl",
}

var generatedPaths = []string{
	".github/workflows/go.yml",
	".github/workflows/deep.yml",
	".github/workflows/release.yml",
	"templates/callers/generated/github-ci.yml",
	"templates/callers/generated/github-ci-deep.yml",
	"templates/callers/generated/github-ci-release.yml",
	"configs/golangci.yml",
}

// Policy is the complete immutable action and tool inventory.
type Policy struct {
	SchemaVersion int        `yaml:"schema-version"`
	GoVersions    GoVersions `yaml:"go-versions"`
	Actions       []Action   `yaml:"actions"`
	Tools         []Tool     `yaml:"tools"`
}

// GoVersions records the current and previous supported Go releases.
type GoVersions struct {
	Current  string `yaml:"current"`
	Previous string `yaml:"previous"`
}

// Action identifies one GitHub Action by release label and immutable commit.
type Action struct {
	ID         string `yaml:"id"`
	Repository string `yaml:"repository"`
	Release    string `yaml:"release"`
	SHA        string `yaml:"sha"`
}

// Tool identifies one checksummed analyzer distribution.
type Tool struct {
	ID             string   `yaml:"id"`
	Version        string   `yaml:"version"`
	Source         string   `yaml:"source"`
	Checksum       string   `yaml:"checksum"`
	Parser         string   `yaml:"parser"`
	Profiles       []string `yaml:"profiles"`
	Acquisition    string   `yaml:"acquisition"`
	VersionCommand string   `yaml:"version-command"`
}

// Linters is the exact golangci-lint baseline.
type Linters struct {
	SchemaVersion int      `yaml:"schema-version"`
	Names         []string `yaml:"linters"`
}

// LoadPolicy strictly decodes and validates one tool-lock document.
func LoadPolicy(reader io.Reader) (Policy, error) {
	var policy Policy
	if err := decodeStrict(reader, &policy); err != nil {
		return Policy{}, err
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

// Validate rejects incomplete, mutable, duplicate, or noncanonical locks.
func (policy Policy) Validate() error {
	if policy.SchemaVersion != schemaVersion {
		return fmt.Errorf("schema-version must be %d", schemaVersion)
	}
	if err := validateVersion("current Go version", policy.GoVersions.Current); err != nil {
		return err
	}
	if err := validateVersion("previous Go version", policy.GoVersions.Previous); err != nil {
		return err
	}
	if policy.GoVersions.Current == policy.GoVersions.Previous {
		return errors.New("current and previous Go versions must differ")
	}
	if len(policy.Actions) == 0 {
		return errors.New("actions must contain at least one lock")
	}
	if len(policy.Tools) == 0 {
		return errors.New("tools must contain at least one lock")
	}

	actions := make(map[string]struct{}, len(policy.Actions))
	previous := ""
	for index, action := range policy.Actions {
		if !idPattern.MatchString(action.ID) {
			return fmt.Errorf("action %d has invalid id %q", index, action.ID)
		}
		if _, exists := actions[action.ID]; exists {
			return fmt.Errorf("duplicate action id %q", action.ID)
		}
		actions[action.ID] = struct{}{}
		if index > 0 && strings.Compare(previous, action.ID) >= 0 {
			return errors.New("actions must be sorted by id")
		}
		previous = action.ID
		if !validRepository(action.Repository) {
			return fmt.Errorf("action %q has invalid repository %q", action.ID, action.Repository)
		}
		if strings.TrimSpace(action.Release) == "" {
			return fmt.Errorf("action %q release must not be empty", action.ID)
		}
		if !actionSHAPattern.MatchString(action.SHA) {
			return fmt.Errorf("action %q sha must be a 40-character lowercase hexadecimal commit SHA", action.ID)
		}
	}

	tools := make(map[string]struct{}, len(policy.Tools))
	previous = ""
	for index, tool := range policy.Tools {
		if !idPattern.MatchString(tool.ID) {
			return fmt.Errorf("tool %d has invalid id %q", index, tool.ID)
		}
		if _, exists := tools[tool.ID]; exists {
			return fmt.Errorf("duplicate tool id %q", tool.ID)
		}
		tools[tool.ID] = struct{}{}
		if index > 0 && strings.Compare(previous, tool.ID) >= 0 {
			return errors.New("tools must be sorted by id")
		}
		previous = tool.ID
		if err := validateVersion("tool "+tool.ID+" version", tool.Version); err != nil {
			return err
		}
		parsed, err := url.Parse(tool.Source)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return fmt.Errorf("tool %q source must be an absolute HTTPS URL", tool.ID)
		}
		if !checksumPattern.MatchString(tool.Checksum) {
			return fmt.Errorf("tool %q checksum must be a SHA-256, SHA-512, or Go module sum", tool.ID)
		}
		if strings.TrimSpace(tool.Parser) == "" {
			return fmt.Errorf("tool %q parser must not be empty", tool.ID)
		}
		if len(tool.Profiles) == 0 {
			return fmt.Errorf("tool %q profiles must not be empty", tool.ID)
		}
		seenProfiles := make(map[string]struct{}, len(tool.Profiles))
		for _, profile := range tool.Profiles {
			if profile != "go-strict" && profile != "go-library" && profile != "repository-only" && profile != "release" && profile != "deep" {
				return fmt.Errorf("tool %q has unsupported profile %q", tool.ID, profile)
			}
			if _, exists := seenProfiles[profile]; exists {
				return fmt.Errorf("tool %q repeats profile %q", tool.ID, profile)
			}
			seenProfiles[profile] = struct{}{}
		}
		if tool.Acquisition != "go-module" && tool.Acquisition != "release-asset" && tool.Acquisition != "pypi-sdist" && tool.Acquisition != "npm-package" && tool.Acquisition != "go-toolchain" {
			return fmt.Errorf("tool %q has unsupported acquisition %q", tool.ID, tool.Acquisition)
		}
		if strings.TrimSpace(tool.VersionCommand) == "" {
			return fmt.Errorf("tool %q version-command must not be empty", tool.ID)
		}
		if strings.ContainsAny(tool.VersionCommand, "\r\n\x00") {
			return fmt.Errorf("tool %q version-command contains a control character", tool.ID)
		}
	}
	return nil
}

// Action returns the immutable action reference for id.
func (policy Policy) Action(id string) (string, error) {
	for _, action := range policy.Actions {
		if action.ID == id {
			return action.Repository + "@" + action.SHA, nil
		}
	}
	return "", fmt.Errorf("action lock %q not found", id)
}

// LoadLinters strictly decodes and validates the 74-linter baseline.
func LoadLinters(reader io.Reader) (Linters, error) {
	var linters Linters
	if err := decodeStrict(reader, &linters); err != nil {
		return Linters{}, err
	}
	if linters.SchemaVersion != schemaVersion {
		return Linters{}, fmt.Errorf("schema-version must be %d", schemaVersion)
	}
	if len(linters.Names) != 74 {
		return Linters{}, fmt.Errorf("linters must contain exactly 74 entries, got %d", len(linters.Names))
	}
	seen := make(map[string]struct{}, len(linters.Names))
	previous := ""
	for index, name := range linters.Names {
		if !idPattern.MatchString(name) {
			return Linters{}, fmt.Errorf("invalid linter %q", name)
		}
		if _, exists := seen[name]; exists {
			return Linters{}, fmt.Errorf("duplicate linter %q", name)
		}
		seen[name] = struct{}{}
		if index > 0 && strings.Compare(previous, name) >= 0 {
			return Linters{}, errors.New("linters must be sorted by name")
		}
		previous = name
	}
	return linters, nil
}

// Generate renders every committed workflow and caller deterministically.
func Generate(root string) error {
	artifacts, err := render(root)
	if err != nil {
		return err
	}
	for _, artifact := range artifacts {
		name := filepath.Join(root, filepath.FromSlash(artifact.name))
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			return fmt.Errorf("create generated directory: %w", err)
		}
		if err := writeAtomic(name, artifact.data); err != nil {
			return err
		}
	}
	return nil
}

// Verify reports every generated artifact that differs from its template.
func Verify(root string) error {
	artifacts, err := render(root)
	if err != nil {
		return err
	}
	var drift []string
	for _, artifact := range artifacts {
		name := filepath.Join(root, filepath.FromSlash(artifact.name))
		data, readErr := os.ReadFile(name)
		if readErr != nil || !bytes.Equal(data, artifact.data) {
			drift = append(drift, artifact.name)
		}
	}
	if len(drift) != 0 {
		return fmt.Errorf("generated artifacts differ: %s", strings.Join(drift, ", "))
	}
	return nil
}

type rendered struct {
	name string
	data []byte
}

type templateData struct {
	Policy  Policy
	Linters []string
}

func (data templateData) Action(id string) (string, error) { return data.Policy.Action(id) }

func render(root string) ([]rendered, error) {
	policyFile, err := os.Open(filepath.Join(root, "policies", "tools.yaml"))
	if err != nil {
		return nil, fmt.Errorf("open tool policy: %w", err)
	}
	policy, err := LoadPolicy(policyFile)
	closeErr := policyFile.Close()
	if err != nil {
		return nil, fmt.Errorf("load tool policy: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close tool policy: %w", closeErr)
	}
	lintersFile, err := os.Open(filepath.Join(root, "policies", "linters.yaml"))
	if err != nil {
		return nil, fmt.Errorf("open linter policy: %w", err)
	}
	linters, err := LoadLinters(lintersFile)
	closeErr = lintersFile.Close()
	if err != nil {
		return nil, fmt.Errorf("load linter policy: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close linter policy: %w", closeErr)
	}

	data := templateData{Policy: policy, Linters: slices.Clone(linters.Names)}
	artifacts := make([]rendered, 0, len(templatePaths))
	for index, templatePath := range templatePaths {
		contents, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(templatePath)))
		if readErr != nil {
			return nil, fmt.Errorf("read template %s: %w", templatePath, readErr)
		}
		parsed, parseErr := template.New(filepath.Base(templatePath)).Delims("[%", "%]").Option("missingkey=error").Parse(string(contents))
		if parseErr != nil {
			return nil, fmt.Errorf("parse template %s: %w", templatePath, parseErr)
		}
		var output bytes.Buffer
		if executeErr := parsed.Execute(&output, data); executeErr != nil {
			return nil, fmt.Errorf("execute template %s: %w", templatePath, executeErr)
		}
		artifacts = append(artifacts, rendered{name: generatedPaths[index], data: output.Bytes()})
	}
	return artifacts, nil
}

func decodeStrict(reader io.Reader, destination any) error {
	if reader == nil {
		return errors.New("YAML reader is nil")
	}
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty YAML document")
		}
		return fmt.Errorf("decode YAML: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("YAML contains multiple documents")
		}
		return fmt.Errorf("decode trailing YAML: %w", err)
	}
	return nil
}

func validateVersion(field, value string) error {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s must not be empty or contain controls", field)
	}
	return nil
}

func validRepository(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 2 && idPattern.MatchString(parts[0]) && regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(parts[1])
}

func writeAtomic(name string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+"-*")
	if err != nil {
		return fmt.Errorf("create generated temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temporary.Close()
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("set generated file mode: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write generated file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync generated file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close generated file: %w", err)
	}
	if err := os.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("replace generated file: %w", err)
	}
	committed = true
	return nil
}
