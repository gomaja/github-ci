package goexecution

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gomaja/github-ci/internal/config"
)

func FuzzResolve(f *testing.F) {
	f.Add("schema-version: 2\nprofile: go-strict\n", ".")
	f.Add(`schema-version: 2
profile: go-library
go:
  defaults:
    build-tags: [sqlite]
  modules:
    - path: .
    - path: tools
      coverage-packages: []
`, ".,tools")
	f.Add("schema-version: 2\nprofile: repository-only\n", "")
	f.Fuzz(func(t *testing.T, document, trackedCSV string) {
		consumer, err := config.DecodeConsumer(strings.NewReader(document))
		if err != nil {
			return
		}
		var tracked []string
		if trackedCSV != "" {
			tracked = strings.Split(trackedCSV, ",")
		}
		plan, err := Resolve(consumer, tracked)
		if err != nil {
			return
		}
		if _, err := json.Marshal(plan); err != nil {
			t.Fatalf("marshal resolved plan: %v", err)
		}
		for _, module := range plan.Modules {
			for _, tool := range tools {
				if _, err := InvocationFor(module, tool); err != nil {
					t.Fatalf("InvocationFor(%q) error = %v", tool, err)
				}
			}
		}
	})
}
