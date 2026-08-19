package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if _, err := Open(""); err == nil || err.Error() != "file path must not be empty" {
		t.Fatalf("Open() error = %v", err)
	}
}

func TestOpenInRootHandlesRootAndChildErrors(t *testing.T) {
	missingRoot := filepath.Join(t.TempDir(), "missing")
	if _, err := OpenInRoot(missingRoot, "value.txt"); err == nil || !strings.Contains(err.Error(), "open filesystem root") {
		t.Fatalf("OpenInRoot(missing root) error = %v", err)
	}
	root := t.TempDir()
	if _, err := OpenInRoot(root, "missing.txt"); err == nil {
		t.Fatal("OpenInRoot() opened a missing child")
	}
	path := filepath.Join(root, "value.txt")
	if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
		t.Fatalf("write value: %v", err)
	}
	file, err := OpenInRoot(root, "value.txt")
	if err != nil {
		t.Fatalf("OpenInRoot() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close value: %v", err)
	}
}

func TestValidateRegularIdentity(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "value.txt")
	if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
		t.Fatalf("write value: %v", err)
	}
	regular, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat value: %v", err)
	}
	directory, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	sentinel := errors.New("stat failed")
	if err := validateRegularIdentity(regular, nil, sentinel); !errors.Is(err, sentinel) {
		t.Fatalf("validateRegularIdentity(stat error) = %v", err)
	}
	if err := validateRegularIdentity(regular, directory, nil); err == nil || err.Error() != "file identity changed while opening" {
		t.Fatalf("validateRegularIdentity(directory) = %v", err)
	}
	if err := validateRegularIdentity(regular, regular, nil); err != nil {
		t.Fatalf("validateRegularIdentity(same file) = %v", err)
	}
}
