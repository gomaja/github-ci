package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunWritesGeneratedModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.go")
	var stderr bytes.Buffer
	if code := run(path, &stderr); code != 0 {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != generatedModel {
		t.Fatalf("generated model = %q, want %q", data, generatedModel)
	}
}

func TestRunReportsWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "model.go")
	var stderr bytes.Buffer
	if code := run(path, &stderr); code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Fatal("run() did not report the write failure")
	}
}
