package release

import (
	"os"
	"path/filepath"
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
