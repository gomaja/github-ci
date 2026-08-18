package generate

import (
	"os"
	"strings"
	"testing"
)

func FuzzLoadPolicy(f *testing.F) {
	seed, err := os.ReadFile("../../policies/tools.yaml")
	if err != nil {
		f.Fatalf("read policy seed: %v", err)
	}
	f.Add(seed)
	f.Add([]byte("schema-version: 1\nactions: []\ntools: []\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadPolicy(strings.NewReader(string(data)))
	})
}

func FuzzLoadLinters(f *testing.F) {
	seed, err := os.ReadFile("../../policies/linters.yaml")
	if err != nil {
		f.Fatalf("read linter seed: %v", err)
	}
	f.Add(seed)
	f.Add([]byte("schema-version: 1\nlinters: []\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadLinters(strings.NewReader(string(data)))
	})
}
