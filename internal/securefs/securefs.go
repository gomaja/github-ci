// Package securefs provides traversal-resistant access to user-selected files and trusted roots.
package securefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Open opens a user-selected file without permitting its final path component to escape its directory.
func Open(name string) (*os.File, error) {
	directory, base, err := split(name)
	if err != nil {
		return nil, err
	}
	return OpenInRoot(directory, base)
}

// ReadFile reads a user-selected file without permitting its final path component to escape its directory.
func ReadFile(name string) ([]byte, error) {
	directory, base, err := split(name)
	if err != nil {
		return nil, err
	}
	return ReadFileInRoot(directory, base)
}

// OpenInRoot opens name only when its complete resolution remains beneath rootName.
func OpenInRoot(rootName, name string) (*os.File, error) {
	root, err := os.OpenRoot(rootName)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	file, openErr := root.Open(name)
	closeErr := root.Close()
	if openErr != nil {
		return nil, openErr
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("close filesystem root: %w", closeErr)
	}
	return file, nil
}

// OpenRegularInRoot opens name only when it is the same regular file observed without following a final symlink.
func OpenRegularInRoot(rootName, name string) (*os.File, error) {
	root, err := os.OpenRoot(rootName)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	observed, lstatErr := root.Lstat(name)
	if lstatErr != nil {
		_ = root.Close()
		return nil, lstatErr
	}
	if !observed.Mode().IsRegular() {
		_ = root.Close()
		return nil, errors.New("path is not a regular file")
	}
	file, openErr := root.Open(name)
	if openErr != nil {
		_ = root.Close()
		return nil, openErr
	}
	opened, statErr := file.Stat()
	if err := validateRegularIdentity(observed, opened, statErr); err != nil {
		_ = file.Close()
		_ = root.Close()
		return nil, err
	}
	if err := root.Close(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("close filesystem root: %w", err)
	}
	return file, nil
}

func validateRegularIdentity(observed, opened os.FileInfo, statErr error) error {
	if statErr != nil {
		return statErr
	}
	if !opened.Mode().IsRegular() || !os.SameFile(observed, opened) {
		return errors.New("file identity changed while opening")
	}
	return nil
}

// ReadFileInRoot reads name only when its complete resolution remains beneath rootName.
func ReadFileInRoot(rootName, name string) ([]byte, error) {
	root, err := os.OpenRoot(rootName)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	data, readErr := root.ReadFile(name)
	closeErr := root.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close filesystem root: %w", closeErr)
	}
	return data, nil
}

func split(name string) (string, string, error) {
	if name == "" {
		return "", "", errors.New("file path must not be empty")
	}
	clean := filepath.Clean(name)
	directory, base := filepath.Dir(clean), filepath.Base(clean)
	if base == "." || base == string(filepath.Separator) {
		return "", "", errors.New("file path must identify a file")
	}
	return directory, base, nil
}
