package securefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFilePreservesExplicitPathsAndRejectsEscapingSymlinks(t *testing.T) {
	directory := t.TempDir()
	inside := filepath.Join(directory, "inside.txt")
	if err := os.WriteFile(inside, []byte("inside"), 0o600); err != nil {
		t.Fatalf("write inside file: %v", err)
	}
	data, err := ReadFile(inside)
	if err != nil || string(data) != "inside" {
		t.Fatalf("ReadFile(inside) = %q, %v", data, err)
	}

	outsideDirectory := t.TempDir()
	outside := filepath.Join(outsideDirectory, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	link := filepath.Join(directory, "escape.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("create escaping symlink: %v", err)
	}
	if _, err := ReadFile(link); err == nil {
		t.Fatal("ReadFile() followed a symlink outside the selected directory")
	}
}

func TestReadFileInRootConfinesEveryPathComponent(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o750); err != nil {
		t.Fatalf("create nested directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "value.txt"), []byte("value"), 0o600); err != nil {
		t.Fatalf("write rooted file: %v", err)
	}
	data, err := ReadFileInRoot(root, filepath.Join("nested", "value.txt"))
	if err != nil || string(data) != "value" {
		t.Fatalf("ReadFileInRoot() = %q, %v", data, err)
	}
	for _, name := range []string{"../outside", filepath.Join(root, "nested", "value.txt")} {
		if _, err := ReadFileInRoot(root, name); err == nil {
			t.Errorf("ReadFileInRoot(%q) accepted an escaping path", name)
		}
	}
}

func TestOpenRegularInRootRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("value"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink("target.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := OpenRegularInRoot(root, "link.txt"); err == nil {
		t.Fatal("OpenRegularInRoot() accepted a symlink")
	}
	file, err := OpenRegularInRoot(root, "target.txt")
	if err != nil {
		t.Fatalf("OpenRegularInRoot(target) error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close target: %v", err)
	}
}

func TestOpenRejectsEmptyName(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("Open() accepted an empty path")
	}
}
