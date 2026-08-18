// Package release creates deterministic, verifiable release evidence.
package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gomaja/github-ci/internal/pathpolicy"
	"github.com/gomaja/github-ci/internal/securefs"
)

const schemaVersion = "1"

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Input identifies source and release artifacts to bind into evidence.
type Input struct {
	Root       string
	SubjectSHA string
	SourceDate time.Time
	Assets     []string
}

// Manifest is the stable release evidence index.
type Manifest struct {
	SchemaVersion string       `json:"schema_version"`
	SubjectSHA    string       `json:"subject_sha"`
	SourceDate    string       `json:"source_date"`
	Files         []FileDigest `json:"files"`
}

// FileDigest binds one repository-relative path to exact bytes.
type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Kind   string `json:"kind"`
}

// Build creates canonical manifest JSON and release-asset SHA256SUMS bytes.
func Build(input Input) ([]byte, []byte, error) {
	if !commitPattern.MatchString(input.SubjectSHA) {
		return nil, nil, errors.New("subject SHA must be a 40-character lowercase hexadecimal commit")
	}
	if input.Root == "" {
		return nil, nil, errors.New("root is required")
	}
	assets, err := validateAssets(input.Assets)
	if err != nil {
		return nil, nil, err
	}
	metadata, err := metadataFiles(input.Root)
	if err != nil {
		return nil, nil, err
	}
	files := make([]FileDigest, 0, len(metadata)+len(assets))
	for _, name := range metadata {
		digest, digestErr := digestFile(input.Root, name, "metadata")
		if digestErr != nil {
			return nil, nil, digestErr
		}
		files = append(files, digest)
	}
	var sums strings.Builder
	for _, name := range assets {
		digest, digestErr := digestFile(input.Root, name, "asset")
		if digestErr != nil {
			return nil, nil, digestErr
		}
		files = append(files, digest)
		fmt.Fprintf(&sums, "%s  %s\n", digest.SHA256, digest.Path)
	}
	slices.SortFunc(files, func(left, right FileDigest) int { return strings.Compare(left.Path, right.Path) })
	manifest := Manifest{
		SchemaVersion: schemaVersion,
		SubjectSHA:    input.SubjectSHA,
		SourceDate:    input.SourceDate.UTC().Truncate(time.Second).Format(time.RFC3339),
		Files:         files,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal release manifest: %w", err)
	}
	return append(data, '\n'), []byte(sums.String()), nil
}

// WriteEvidence atomically writes a release manifest and checksum file.
func WriteEvidence(input Input, manifestPath, sumsPath string) error {
	manifest, sums, err := Build(input)
	if err != nil {
		return err
	}
	if err := writeAtomic(manifestPath, manifest); err != nil {
		return err
	}
	return writeAtomic(sumsPath, sums)
}

// Verify proves that a manifest, checksum file, and current artifact bytes agree.
func Verify(root, manifestPath, sumsPath string) error {
	manifestData, err := securefs.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read release manifest: %w", err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode release manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("release manifest contains trailing data")
	}
	if manifest.SchemaVersion != schemaVersion || !commitPattern.MatchString(manifest.SubjectSHA) {
		return errors.New("invalid release manifest identity")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	var sums strings.Builder
	previous := ""
	for _, expected := range manifest.Files {
		if err := pathpolicy.Validate("release file", expected.Path); err != nil {
			return err
		}
		if _, exists := seen[expected.Path]; exists || previous != "" && strings.Compare(previous, expected.Path) >= 0 {
			return errors.New("release manifest files must be unique and sorted")
		}
		seen[expected.Path] = struct{}{}
		previous = expected.Path
		observed, digestErr := digestFile(root, expected.Path, expected.Kind)
		if digestErr != nil {
			return digestErr
		}
		if observed != expected {
			return fmt.Errorf("release file %q does not match manifest", expected.Path)
		}
		if expected.Kind == "asset" {
			fmt.Fprintf(&sums, "%s  %s\n", expected.SHA256, expected.Path)
		}
	}
	actualSums, err := securefs.ReadFile(sumsPath)
	if err != nil {
		return fmt.Errorf("read SHA256SUMS: %w", err)
	}
	if !bytes.Equal(actualSums, []byte(sums.String())) {
		return errors.New("SHA256SUMS does not match release manifest")
	}
	return nil
}

func validateAssets(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one release asset is required")
	}
	assets := slices.Clone(values)
	slices.Sort(assets)
	for index, name := range assets {
		if err := pathpolicy.Validate("release asset", name); err != nil {
			return nil, err
		}
		if index > 0 && assets[index-1] == name {
			return nil, fmt.Errorf("duplicate release asset %q", name)
		}
	}
	return assets, nil
}

func metadataFiles(root string) ([]string, error) {
	var names []string
	for _, directory := range []string{".github/workflows", "policies", "schemas"} {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(directory)), func(name string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(root, name)
			if err != nil {
				return err
			}
			names = append(names, filepath.ToSlash(relative))
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk release metadata %s: %w", directory, err)
		}
	}
	slices.Sort(names)
	return names, nil
}

func digestFile(root, name, kind string) (FileDigest, error) {
	if kind != "asset" && kind != "metadata" {
		return FileDigest{}, fmt.Errorf("unsupported release file kind %q", kind)
	}
	file, err := securefs.OpenRegularInRoot(root, filepath.FromSlash(name))
	if err != nil {
		return FileDigest{}, fmt.Errorf("open release file %q: %w", name, err)
	}
	data, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		return FileDigest{}, fmt.Errorf("read release file %q: %w", name, readErr)
	}
	if closeErr != nil {
		return FileDigest{}, fmt.Errorf("close release file %q: %w", name, closeErr)
	}
	digest := sha256.Sum256(data)
	return FileDigest{Path: name, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(data)), Kind: kind}, nil
}

func writeAtomic(name string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(name), ".release-*")
	if err != nil {
		return fmt.Errorf("create temporary evidence: %w", err)
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
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, name); err != nil {
		return err
	}
	committed = true
	return nil
}
