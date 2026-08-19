package config

import (
	"strings"
	"testing"
)

func FuzzDecodeConsumer(f *testing.F) {
	for _, seed := range []string{
		validConsumerV2,
		"schema-version: 1\nprofile: go-strict\n",
		"schema-version: 2\nprofile: repository-only\n",
		"schema-version: 2\nprofile: go-strict\ngo:\n  defaults:\n    coverage-packages: []\n",
		"schema-version: 2\nprofile: go-strict\n---\n{}\n",
		"&alias [*alias]\n",
		"\x00",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, input string) {
		_, _ = DecodeConsumer(strings.NewReader(input))
	})
}

func FuzzDecodeGovernance(f *testing.F) {
	for _, seed := range []string{
		validGovernanceV2,
		"schema-version: 1\n",
		"schema-version: 2\napi-version: 2026-03-10\n",
		"schema-version: 2\n---\n{}\n",
		"\x00",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, input string) {
		_, _ = DecodeGovernance(strings.NewReader(input))
	})
}
