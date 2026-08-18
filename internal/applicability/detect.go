package applicability

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/evidence"
)

const (
	DetectorVersion = "applicability/v1"
	maxTrackedFile  = 256 << 20
	maxTrackedTree  = 2 << 30
)

// Input binds detection to consumer configuration and immutable policy identity.
type Input struct {
	Consumer     config.Consumer
	SubjectSHA   string
	PolicySHA256 string
	Catalog      Catalog
}

type trackedFile struct {
	path string
	mode fs.FileMode
	data []byte
}

type repositoryShape struct {
	modules    []string
	ordinaryGo bool
	shell      bool
	docker     bool
	workflow   bool
	terraform  bool
	markdown   bool
	yaml       bool
	json       bool
}

// Detect builds a deterministic assurance plan from a tracked-only file system.
func Detect(tracked fs.FS, input Input) (evidence.Plan, error) {
	if tracked == nil {
		return evidence.Plan{}, fmt.Errorf("tracked filesystem must not be nil")
	}
	if err := input.Consumer.Validate(); err != nil {
		return evidence.Plan{}, fmt.Errorf("consumer configuration: %w", err)
	}
	if err := input.Catalog.Validate(); err != nil {
		return evidence.Plan{}, fmt.Errorf("catalog: %w", err)
	}
	if err := input.Catalog.validateDefaultPolicy(); err != nil {
		return evidence.Plan{}, err
	}
	files, err := readTrackedFiles(tracked)
	if err != nil {
		return evidence.Plan{}, err
	}
	if input.Consumer.Exceptions != "" && !slices.ContainsFunc(files, func(file trackedFile) bool {
		return file.path == input.Consumer.Exceptions
	}) {
		return evidence.Plan{}, fmt.Errorf("configured exceptions manifest %q is not tracked", input.Consumer.Exceptions)
	}
	shape := inspect(files, input.Consumer.Generated)
	if err := validateModules(input.Consumer, shape.modules); err != nil {
		return evidence.Plan{}, err
	}

	expected := make([]evidence.Expected, 0, len(input.Catalog))
	for _, entry := range input.Catalog {
		if !slices.Contains(entry.Profiles, input.Consumer.Profile) {
			continue
		}
		applicable := capabilityApplies(entry.Capability, shape)
		item := evidence.Expected{
			Tool:          entry.Tool,
			CommandID:     entry.CommandID,
			ParserVersion: entry.ParserVersion,
			Applicability: evidence.Applicable,
		}
		if !applicable {
			item.Applicability = evidence.NotApplicable
			item.ReasonCode = entry.ReasonCode
		}
		expected = append(expected, item)
	}
	slices.SortFunc(expected, func(left, right evidence.Expected) int {
		return strings.Compare(left.Identity(), right.Identity())
	})
	plan := evidence.Plan{
		SchemaVersion:   evidence.SchemaVersion,
		DetectorVersion: DetectorVersion,
		SubjectSHA:      input.SubjectSHA,
		TreeSHA256:      treeDigest(files),
		PolicySHA256:    input.PolicySHA256,
		Expected:        expected,
	}
	if err := evidence.ValidatePlan(plan); err != nil {
		return evidence.Plan{}, fmt.Errorf("validate applicability plan: %w", err)
	}
	return plan, nil
}

func readTrackedFiles(tracked fs.FS) ([]trackedFile, error) {
	var files []trackedFile
	var total int64
	err := fs.WalkDir(tracked, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk tracked path %q: %w", name, walkErr)
		}
		if name == "." || entry.IsDir() {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("tracked path %q is a symlink", name)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat tracked path %q: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("tracked path %q has unsupported file mode %s", name, info.Mode())
		}
		if info.Size() > maxTrackedFile {
			return fmt.Errorf("tracked path %q exceeds %d bytes", name, maxTrackedFile)
		}
		file, err := tracked.Open(name)
		if err != nil {
			return fmt.Errorf("open tracked path %q: %w", name, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxTrackedFile+1))
		closeErr := file.Close()
		if readErr != nil {
			return fmt.Errorf("read tracked path %q: %w", name, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close tracked path %q: %w", name, closeErr)
		}
		if len(data) > maxTrackedFile {
			return fmt.Errorf("tracked path %q exceeds %d bytes", name, maxTrackedFile)
		}
		total += int64(len(data))
		if total > maxTrackedTree {
			return fmt.Errorf("tracked tree exceeds %d bytes", maxTrackedTree)
		}
		files = append(files, trackedFile{path: name, mode: info.Mode(), data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(left, right trackedFile) int { return strings.Compare(left.path, right.path) })
	return files, nil
}

func inspect(files []trackedFile, generated []string) repositoryShape {
	shape := repositoryShape{}
	for _, file := range files {
		base := path.Base(file.path)
		extension := strings.ToLower(path.Ext(base))
		if base == "go.mod" {
			root := path.Dir(file.path)
			if root == "." {
				root = "."
			}
			shape.modules = append(shape.modules, root)
		}
		if extension == ".go" && !isGenerated(file.path, generated) {
			shape.ordinaryGo = true
		}
		if isShell(file, extension) {
			shape.shell = true
		}
		if isDockerfile(base) {
			shape.docker = true
		}
		if strings.HasPrefix(file.path, ".github/workflows/") && (extension == ".yml" || extension == ".yaml") {
			shape.workflow = true
		}
		if extension == ".tf" {
			shape.terraform = true
		}
		if extension == ".md" || extension == ".markdown" {
			shape.markdown = true
		}
		if extension == ".yml" || extension == ".yaml" {
			shape.yaml = true
		}
		if extension == ".json" {
			shape.json = true
		}
	}
	slices.Sort(shape.modules)
	return shape
}

func validateModules(consumer config.Consumer, detected []string) error {
	isGoProfile := consumer.Profile == config.ProfileGoStrict || consumer.Profile == config.ProfileGoLibrary
	if isGoProfile && len(detected) == 0 {
		return fmt.Errorf("profile %q requires a tracked go.mod", consumer.Profile)
	}
	if !isGoProfile && len(detected) != 0 {
		return fmt.Errorf("profile %q would omit tracked Go modules", consumer.Profile)
	}
	if len(consumer.Modules) == 0 {
		return nil
	}
	configured := make([]string, len(consumer.Modules))
	for index, module := range consumer.Modules {
		configured[index] = string(module)
	}
	slices.Sort(configured)
	for _, module := range configured {
		if !slices.Contains(detected, module) {
			return fmt.Errorf("configured module %q has no tracked go.mod", module)
		}
	}
	for _, module := range detected {
		if !slices.Contains(configured, module) {
			return fmt.Errorf("configuration omits tracked module %q", module)
		}
	}
	return nil
}

func capabilityApplies(capability Capability, shape repositoryShape) bool {
	switch capability {
	case CapabilityAlways:
		return true
	case CapabilityGo:
		return len(shape.modules) != 0
	case CapabilityOrdinaryGo:
		return shape.ordinaryGo
	case CapabilityShell:
		return shape.shell
	case CapabilityDocker:
		return shape.docker
	case CapabilityWorkflow:
		return shape.workflow
	case CapabilityTerraform:
		return shape.terraform
	case CapabilityMarkdown:
		return shape.markdown
	case CapabilityYAML:
		return shape.yaml
	case CapabilityJSON:
		return shape.json
	default:
		return false
	}
}

func isGenerated(name string, generated []string) bool {
	for _, prefix := range generated {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	return false
}

func isShell(file trackedFile, extension string) bool {
	switch extension {
	case ".sh", ".bash", ".bats", ".zsh", ".ksh":
		return true
	}
	if file.mode.Perm()&0o111 == 0 {
		return false
	}
	line, _, _ := bytes.Cut(file.data, []byte("\n"))
	return bytes.HasPrefix(line, []byte("#!/bin/sh")) ||
		bytes.HasPrefix(line, []byte("#!/bin/bash")) ||
		bytes.HasPrefix(line, []byte("#!/bin/zsh")) ||
		bytes.HasPrefix(line, []byte("#!/bin/ksh")) ||
		bytes.HasPrefix(line, []byte("#!/usr/bin/env sh")) ||
		bytes.HasPrefix(line, []byte("#!/usr/bin/env bash")) ||
		bytes.HasPrefix(line, []byte("#!/usr/bin/env zsh")) ||
		bytes.HasPrefix(line, []byte("#!/usr/bin/env ksh"))
}

func isDockerfile(base string) bool {
	lower := strings.ToLower(base)
	return lower == "dockerfile" || lower == "containerfile" ||
		strings.HasPrefix(lower, "dockerfile.") || strings.HasPrefix(lower, "containerfile.") ||
		strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile")
}

func treeDigest(files []trackedFile) string {
	hash := sha256.New()
	var integer [8]byte
	for _, file := range files {
		binary.BigEndian.PutUint64(integer[:], uint64(len(file.path)))
		_, _ = hash.Write(integer[:])
		_, _ = hash.Write([]byte(file.path))
		binary.BigEndian.PutUint64(integer[:], uint64(file.mode))
		_, _ = hash.Write(integer[:])
		binary.BigEndian.PutUint64(integer[:], uint64(len(file.data)))
		_, _ = hash.Write(integer[:])
		_, _ = hash.Write(file.data)
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}
