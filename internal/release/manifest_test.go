package release

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBuildIsDeterministicAndSorted(t *testing.T) {
	root := fixtureRoot(t)
	input := Input{
		Root: root, SubjectSHA: strings.Repeat("a", 40),
		SourceDate: time.Date(2026, 8, 19, 2, 3, 4, 500, time.FixedZone("offset", 2*60*60)),
		Assets:     []string{"dist/z.txt", "dist/a.txt"},
	}
	first, firstSums, err := Build(input)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	second, secondSums, err := Build(input)
	if err != nil {
		t.Fatalf("Build() second error = %v", err)
	}
	if string(first) != string(second) || string(firstSums) != string(secondSums) {
		t.Fatal("Build() is not deterministic")
	}
	if !strings.Contains(string(first), `"source_date":"2026-08-19T00:03:04Z"`) {
		t.Fatalf("manifest does not normalize source date: %s", first)
	}
	if strings.Index(string(firstSums), "dist/a.txt") > strings.Index(string(firstSums), "dist/z.txt") {
		t.Fatalf("checksums are not sorted: %s", firstSums)
	}
	for _, name := range []string{".github/workflows/go.yml", "policies/tools.yaml", "schemas/evidence.json"} {
		if !strings.Contains(string(first), `"path":"`+name+`"`) {
			t.Errorf("manifest omitted metadata %q: %s", name, first)
		}
	}
}

func TestWriteEvidenceCreatesVerifiableAtomicFiles(t *testing.T) {
	root := fixtureRoot(t)
	manifestPath := filepath.Join(t.TempDir(), "nested", "release-manifest.json")
	sumsPath := filepath.Join(t.TempDir(), "nested", "SHA256SUMS")
	input := Input{
		Root: root, SubjectSHA: strings.Repeat("c", 40), SourceDate: time.Unix(1, 0),
		Assets: []string{"dist/a.txt"},
	}
	if err := WriteEvidence(input, manifestPath, sumsPath); err != nil {
		t.Fatalf("WriteEvidence() error = %v", err)
	}
	if err := Verify(root, manifestPath, sumsPath); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	for _, name := range []string{manifestPath, sumsPath} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
			t.Errorf("%s permissions = %o, want 644", name, info.Mode().Perm())
		}
	}
}

func TestWriteAtomicReturnsRenameFailure(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "existing-directory")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create rename target: %v", err)
	}
	if err := writeAtomic(target, []byte("evidence")); err == nil {
		t.Fatal("writeAtomic() error = nil, want rename failure")
	}
}

func TestVerifyRejectsDuplicateAndUnsortedManifestFiles(t *testing.T) {
	root := fixtureRoot(t)
	manifestData, sums, err := Build(Input{
		Root: root, SubjectSHA: strings.Repeat("d", 40), SourceDate: time.Unix(1, 0),
		Assets: []string{"dist/a.txt"},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	var canonical Manifest
	if err := json.Unmarshal(manifestData, &canonical); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if len(canonical.Files) < 2 {
		t.Fatalf("manifest files = %d, want at least two", len(canonical.Files))
	}

	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "duplicate", mutate: func(manifest *Manifest) { manifest.Files[1] = manifest.Files[0] }},
		{name: "unsorted", mutate: func(manifest *Manifest) { manifest.Files[0], manifest.Files[1] = manifest.Files[1], manifest.Files[0] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := canonical
			manifest.Files = append([]FileDigest(nil), canonical.Files...)
			test.mutate(&manifest)
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatalf("marshal manifest: %v", err)
			}
			manifestPath := filepath.Join(t.TempDir(), "manifest.json")
			sumsPath := filepath.Join(t.TempDir(), "SHA256SUMS")
			mustWrite(t, manifestPath, data)
			mustWrite(t, sumsPath, sums)
			if err := Verify(root, manifestPath, sumsPath); err == nil || err.Error() != "release manifest files must be unique and sorted" {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestVerifyRejectsEitherInvalidManifestIdentityField(t *testing.T) {
	root := fixtureRoot(t)
	manifestData, sums, err := Build(Input{
		Root: root, SubjectSHA: strings.Repeat("d", 40), SourceDate: time.Unix(1, 0), Assets: []string{"dist/a.txt"},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	var canonical Manifest
	if err := json.Unmarshal(manifestData, &canonical); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "schema version", mutate: func(manifest *Manifest) { manifest.SchemaVersion = "2" }},
		{name: "subject SHA", mutate: func(manifest *Manifest) { manifest.SubjectSHA = "main" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := canonical
			test.mutate(&manifest)
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatalf("marshal manifest: %v", err)
			}
			manifestPath := filepath.Join(t.TempDir(), "manifest.json")
			sumsPath := filepath.Join(t.TempDir(), "SHA256SUMS")
			mustWrite(t, manifestPath, data)
			mustWrite(t, sumsPath, sums)
			if err := Verify(root, manifestPath, sumsPath); err == nil || err.Error() != "invalid release manifest identity" {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestBuildRejectsMissingMetadataDirectories(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "dist", "asset.txt"), []byte("asset"))
	_, _, err := Build(Input{
		Root: root, SubjectSHA: strings.Repeat("e", 40), SourceDate: time.Unix(1, 0),
		Assets: []string{"dist/asset.txt"},
	})
	if err == nil || !strings.Contains(err.Error(), "walk release metadata") {
		t.Fatalf("Build() error = %v", err)
	}
}

func TestBuildRejectsUnsafeOrDuplicateAssets(t *testing.T) {
	root := fixtureRoot(t)
	for _, assets := range [][]string{{"../escape"}, {"/absolute"}, {"dist/a.txt", "dist/a.txt"}, {"dist/missing"}} {
		_, _, err := Build(Input{Root: root, SubjectSHA: strings.Repeat("a", 40), SourceDate: time.Now(), Assets: assets})
		if err == nil {
			t.Fatalf("Build(%v) accepted unsafe assets", assets)
		}
	}
}

func TestVerifyDetectsChangedOrMissingAssets(t *testing.T) {
	root := fixtureRoot(t)
	manifest, sums, err := Build(Input{Root: root, SubjectSHA: strings.Repeat("b", 40), SourceDate: time.Unix(0, 0), Assets: []string{"dist/a.txt"}})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	manifestPath := filepath.Join(root, "release-manifest.json")
	sumsPath := filepath.Join(root, "SHA256SUMS")
	mustWrite(t, manifestPath, manifest)
	mustWrite(t, sumsPath, sums)
	if err := Verify(root, manifestPath, sumsPath); err != nil {
		t.Fatalf("Verify(clean) error = %v", err)
	}
	mustWrite(t, filepath.Join(root, "dist", "a.txt"), []byte("changed"))
	if err := Verify(root, manifestPath, sumsPath); err == nil {
		t.Fatal("Verify() accepted changed bytes")
	}
	if err := os.Remove(filepath.Join(root, "dist", "a.txt")); err != nil {
		t.Fatalf("remove asset: %v", err)
	}
	if err := Verify(root, manifestPath, sumsPath); err == nil {
		t.Fatal("Verify() accepted missing asset")
	}
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range map[string]string{
		"dist/a.txt": "a", "dist/z.txt": "z",
		".github/workflows/go.yml": "name: go\n",
		"policies/tools.yaml":      "schema-version: 1\n",
		"schemas/evidence.json":    "{}\n",
	} {
		mustWrite(t, filepath.Join(root, filepath.FromSlash(name)), []byte(data))
	}
	return root
}

func mustWrite(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(name, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
