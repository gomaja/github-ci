package governance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gomaja/github-ci/internal/config"
	"gopkg.in/yaml.v3"
)

var immutableSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// RenderCallers writes consumer configuration and SHA-pinned caller workflows.
func RenderCallers(manifest config.Governance, output, workflowSHA, onlyRepository string) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if !immutableSHAPattern.MatchString(workflowSHA) {
		return errors.New("workflow SHA must be an immutable 40-character lowercase hexadecimal commit SHA")
	}
	if output == "" {
		return errors.New("caller output directory must not be empty")
	}
	rendered := false
	for _, repository := range manifest.Repositories {
		if onlyRepository != "" && repository.Name != onlyRepository {
			continue
		}
		owner := repository.Owner
		if owner == "" {
			owner = manifest.Owners[0].Name
		}
		profile := repositoryProfile(repository.Profile, manifest.Defaults.Profile)
		consumer := config.Consumer{
			SchemaVersion:  2,
			Profile:        profile,
			Go:             repository.Go,
			GeneratedPaths: repository.GeneratedPaths,
			Exceptions:     repository.Exceptions,
		}
		consumerYAML, err := yaml.Marshal(consumer)
		if err != nil {
			return fmt.Errorf("render %s/%s consumer configuration: %w", owner, repository.Name, err)
		}
		root := filepath.Join(output, owner, repository.Name)
		files := map[string][]byte{
			filepath.Join(".github", "github-ci.yaml"):                     consumerYAML,
			filepath.Join(".github", "workflows", "github-ci.yml"):         []byte(standardCaller(workflowSHA)),
			filepath.Join(".github", "workflows", "github-ci-deep.yml"):    []byte(deepCaller(workflowSHA)),
			filepath.Join(".github", "workflows", "github-ci-release.yml"): []byte(releaseCaller(workflowSHA)),
		}
		for name, data := range files {
			if err := writeFileAtomic(filepath.Join(root, name), data, 0o644); err != nil {
				return err
			}
		}
		rendered = true
	}
	if !rendered {
		return fmt.Errorf("repository %q is not present in the governance manifest", onlyRepository)
	}
	return nil
}

func repositoryProfile(configured, fallback config.Profile) config.Profile {
	if configured != "" {
		return configured
	}
	return fallback
}

func standardCaller(sha string) string {
	return fmt.Sprintf(`# github-ci commit %s
name: github-ci

on:
  pull_request:
  push:
    branches: [main]
  merge_group:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  gate:
    permissions:
      contents: read
      security-events: write  # CodeQL publishes results evaluated by the local gate.
    uses: gomaja/github-ci/.github/workflows/go.yml@%s
`, sha, sha)
}

func deepCaller(sha string) string {
	return fmt.Sprintf(`# github-ci commit %s
name: github-ci-deep

on:
  schedule:
    - cron: "17 3 * * 1"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  assurance:
    uses: gomaja/github-ci/.github/workflows/deep.yml@%s
`, sha, sha)
}

func releaseCaller(sha string) string {
	return fmt.Sprintf(`# github-ci commit %s
name: github-ci-release

on:
  push:
    tags: ["v*"]
  workflow_dispatch:
    inputs:
      tag:
        description: Existing immutable semantic-version tag to validate.
        required: true
        type: string

permissions:
  contents: read

jobs:
  assurance:
    permissions:
      contents: read
      id-token: write  # Provenance attestation requires an OIDC identity.
      attestations: write  # The called workflow records build provenance.
    uses: gomaja/github-ci/.github/workflows/release.yml@%s
    with:
      tag: ${{ inputs.tag }}
`, sha, sha)
}

func writeFileAtomic(name string, data []byte, mode os.FileMode) error {
	if strings.ContainsRune(name, '\x00') {
		return errors.New("output path contains a null byte")
	}
	if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(name), ".github-ci-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set output permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(temporaryName, name); err != nil {
		return fmt.Errorf("replace output: %w", err)
	}
	return nil
}
