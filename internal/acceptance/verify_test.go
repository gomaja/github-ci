package acceptance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const (
	testCandidateSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testConsumerSHA  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testForkSHA      = "cccccccccccccccccccccccccccccccccccccccc"
	testCanary       = "acme/go-canary"
	testFork         = "forker/go-canary"
)

func TestValidateInputRejectsEachInvalidIdentity(t *testing.T) {
	valid := Input{
		CandidateSHA: testCandidateSHA, CanaryRepository: testCanary,
		StandardRunID: 101, DeepRunID: 102, ForkRunID: 103,
	}
	tests := []struct {
		name   string
		mutate func(*Input)
		want   string
	}{
		{name: "candidate SHA", mutate: func(input *Input) { input.CandidateSHA = "main" }, want: "40-character"},
		{name: "repository syntax", mutate: func(input *Input) { input.CanaryRepository = "invalid" }, want: "different owner/repository"},
		{name: "central repository", mutate: func(input *Input) { input.CanaryRepository = "gomaja/github-ci" }, want: "different owner/repository"},
		{name: "zero standard run", mutate: func(input *Input) { input.StandardRunID = 0 }, want: "positive"},
		{name: "zero deep run", mutate: func(input *Input) { input.DeepRunID = 0 }, want: "positive"},
		{name: "zero fork run", mutate: func(input *Input) { input.ForkRunID = 0 }, want: "positive"},
		{name: "standard equals deep", mutate: func(input *Input) { input.DeepRunID = input.StandardRunID }, want: "distinct"},
		{name: "standard equals fork", mutate: func(input *Input) { input.ForkRunID = input.StandardRunID }, want: "distinct"},
		{name: "deep equals fork", mutate: func(input *Input) { input.ForkRunID = input.DeepRunID }, want: "distinct"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.mutate(&input)
			if err := validateInput(input); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateInput() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateWorkflowRunRejectsZeroAttemptAtIdentityBoundary(t *testing.T) {
	run := workflowRun{
		ID: 101, Name: "github-ci", Event: manualDispatchEvent, Status: "completed", Conclusion: "success",
		HeadBranch: "main", HeadSHA: testConsumerSHA, Path: standardCallerPath,
		Repository: repository{FullName: testCanary}, HeadRepository: repository{FullName: testCanary},
	}
	expected := scenario{kind: RunStandard, runID: 101, workflowPath: standardCallerPath, event: manualDispatchEvent}
	err := validateWorkflowRun(run, Input{CanaryRepository: testCanary}, expected)
	if err == nil || err.Error() != "workflow run attempt, head branch, or head SHA is invalid" {
		t.Fatalf("validateWorkflowRun(zero attempt) error = %v", err)
	}
}

func TestGeneratedPathMatchingCoversEveryBoundary(t *testing.T) {
	tests := []struct {
		path string
		root string
		want bool
	}{
		{path: "generated/model.go", root: ".", want: true},
		{path: "generated", root: "generated", want: true},
		{path: "generated/model.go", root: "generated", want: true},
		{path: "generated-other/model.go", root: "generated", want: false},
	}
	for _, test := range tests {
		if got := generatedPathContains(test.root, test.path); got != test.want {
			t.Errorf("generatedPathContains(%q, %q) = %t, want %t", test.root, test.path, got, test.want)
		}
	}
}

func TestValidateGitTreePathRejectsEmptyAndAbsoluteIndependently(t *testing.T) {
	for _, value := range []string{"", "/generated/model.go"} {
		if err := validateGitTreePath(value); err == nil || !strings.Contains(err.Error(), "nonempty relative path") {
			t.Fatalf("validateGitTreePath(%q) error = %v", value, err)
		}
	}
}

func TestForkPullMatcherRejectsEveryIdentityBoundary(t *testing.T) {
	run := workflowRun{HeadSHA: testForkSHA, HeadRepository: repository{FullName: testFork}}
	valid := pullRequest{Number: 7}
	valid.Head.SHA = testForkSHA
	valid.Head.Repo = repository{FullName: testFork, Fork: true}
	valid.Base.Repo = repository{FullName: testCanary}
	tests := []struct {
		name   string
		mutate func(*pullRequest)
	}{
		{name: "zero number", mutate: func(pull *pullRequest) { pull.Number = 0 }},
		{name: "head SHA", mutate: func(pull *pullRequest) { pull.Head.SHA = testConsumerSHA }},
		{name: "head repository", mutate: func(pull *pullRequest) { pull.Head.Repo.FullName = testCanary }},
		{name: "private head", mutate: func(pull *pullRequest) { pull.Head.Repo.Private = true }},
		{name: "non-fork head", mutate: func(pull *pullRequest) { pull.Head.Repo.Fork = false }},
		{name: "base repository", mutate: func(pull *pullRequest) { pull.Base.Repo.FullName = testFork }},
		{name: "private base", mutate: func(pull *pullRequest) { pull.Base.Repo.Private = true }},
		{name: "fork base", mutate: func(pull *pullRequest) { pull.Base.Repo.Fork = true }},
	}
	if !matchesForkPull(valid, testCanary, run) {
		t.Fatal("matchesForkPull() rejected valid pull")
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pull := valid
			test.mutate(&pull)
			if matchesForkPull(pull, testCanary, run) {
				t.Fatal("matchesForkPull() accepted invalid pull")
			}
		})
	}
}

func TestVerifyBindsSuccessfulRunsCallerConfigAndFork(t *testing.T) {
	fixture := newAcceptanceFixture()
	record, err := fixture.verify(t)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	digest := sha256.Sum256([]byte(fixture.config))
	want := Record{
		SchemaVersion:    SchemaVersion,
		CandidateSHA:     testCandidateSHA,
		CanaryRepository: testCanary,
		Runs: []RunRecord{
			{Kind: RunStandard, ID: 101, Repository: testCanary, HeadRepository: testCanary, Event: "workflow_dispatch", HeadSHA: testConsumerSHA, WorkflowPath: ".github/workflows/github-ci.yml", WorkflowSHA: testCandidateSHA, GateJob: "gate / gate"},
			{Kind: RunDeep, ID: 102, Repository: testCanary, HeadRepository: testCanary, Event: "workflow_dispatch", HeadSHA: testConsumerSHA, WorkflowPath: ".github/workflows/github-ci-deep.yml", WorkflowSHA: testCandidateSHA, GateJob: "assurance / gate"},
			{Kind: RunFork, ID: 103, Repository: testCanary, HeadRepository: testFork, Event: "pull_request", HeadSHA: testForkSHA, WorkflowPath: ".github/workflows/github-ci.yml", WorkflowSHA: testCandidateSHA, GateJob: "gate / gate", PullRequest: 7},
		},
		ConfigSHA256: hex.EncodeToString(digest[:]),
	}
	if got, wantJSON := mustJSON(t, record), mustJSON(t, want); got != wantJSON {
		t.Fatalf("Record = %s, want %s", got, wantJSON)
	}
	if err := ValidateRecord(record, testCandidateSHA); err != nil {
		t.Fatalf("ValidateRecord() error = %v", err)
	}
}

func TestVerifyAcceptsExplicitPackageLocalCoverage(t *testing.T) {
	fixture := newAcceptanceFixture()
	fixture.config = strings.Replace(fixture.config, "coverage-packages: [./...]", "coverage-packages: []", 1)
	fixture.forkConfig = fixture.config
	if _, err := fixture.verify(t); err != nil {
		t.Fatalf("Verify() with package-local coverage error = %v", err)
	}
}

func TestVerifyAcceptsGoStrictProfile(t *testing.T) {
	fixture := newAcceptanceFixture()
	fixture.config = strings.Replace(fixture.config, "profile: go-library", "profile: go-strict", 1)
	fixture.forkConfig = fixture.config
	if _, err := fixture.verify(t); err != nil {
		t.Fatalf("Verify() with go-strict profile error = %v", err)
	}
}

func TestVerifyFindsGeneratedGoInNestedDirectories(t *testing.T) {
	fixture := newAcceptanceFixture()
	for _, repository := range []string{testCanary, testFork} {
		fixture.trees[repository] = []map[string]any{
			gitTreeFixture("generated", "040000", "tree"),
			gitTreeFixture("generated/api", "040000", "tree"),
			gitTreeFixture("generated/api/model.go", "100644", "blob"),
		}
	}
	if _, err := fixture.verify(t); err != nil {
		t.Fatalf("Verify() with nested generated Go error = %v", err)
	}
}

func TestVerifyAllowsUnrelatedLegalGitPathsOutsideGeneratedRoots(t *testing.T) {
	fixture := newAcceptanceFixture()
	fixture.trees[testCanary] = append(fixture.trees[testCanary], gitTreeFixture("docs/Release Notes.md", "100644", "blob"))
	if _, err := fixture.verify(t); err != nil {
		t.Fatalf("Verify() with unrelated legal Git path error = %v", err)
	}
}

func TestVerifyAllowsLegalGitNamesInsideGeneratedRoots(t *testing.T) {
	fixture := newAcceptanceFixture()
	for _, repository := range []string{testCanary, testFork} {
		fixture.trees[repository][1]["path"] = "generated/Release Notes.go"
	}
	if _, err := fixture.verify(t); err != nil {
		t.Fatalf("Verify() with legal generated Git path error = %v", err)
	}

	fixture = newAcceptanceFixture()
	fixture.config = strings.Replace(fixture.config, "  - generated\n", "  - .\n", 1)
	fixture.forkConfig = fixture.config
	fixture.trees[testCanary] = append(fixture.trees[testCanary], gitTreeFixture("docs/Release Notes.md", "100644", "blob"))
	if _, err := fixture.verify(t); err != nil {
		t.Fatalf("Verify() with repository-root generated scope error = %v", err)
	}
}

func TestVerifyRejectsGeneratedGoThatIsNotARegularBlob(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		objectType string
		want       string
	}{
		{name: "symlink", mode: "120000", objectType: "blob", want: "regular tracked Go source"},
		{name: "submodule", mode: "160000", objectType: "commit", want: "regular tracked Go source"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAcceptanceFixture()
			fixture.trees[testCanary] = []map[string]any{
				gitTreeFixture("generated", "040000", "tree"),
				gitTreeFixture("generated/model.go", test.mode, test.objectType),
			}
			if _, err := fixture.verify(t); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Verify() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestVerifyRejectsEveryUnprovenCondition(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*acceptanceFixture)
		want   string
	}{
		{name: "HTTP 404", mutate: func(f *acceptanceFixture) { f.status["/repos/"+testCanary] = http.StatusNotFound }, want: "404"},
		{name: "HTTP 403", mutate: func(f *acceptanceFixture) { f.status["/repos/"+testCanary] = http.StatusForbidden }, want: "403"},
		{name: "HTTP 500", mutate: func(f *acceptanceFixture) { f.status["/repos/"+testCanary] = http.StatusInternalServerError }, want: "500"},
		{name: "malformed JSON", mutate: func(f *acceptanceFixture) { f.raw["/repos/"+testCanary] = "{" }, want: "decode"},
		{name: "unknown JSON field", mutate: func(f *acceptanceFixture) { f.repository["unknown"] = true }, want: "unknown field"},
		{name: "missing private state", mutate: func(f *acceptanceFixture) { delete(f.repository, "private") }, want: `missing "private"`},
		{name: "missing fork state", mutate: func(f *acceptanceFixture) { delete(f.repository, "fork") }, want: `missing "fork"`},
		{name: "missing archived state", mutate: func(f *acceptanceFixture) { delete(f.repository, "archived") }, want: `missing "archived"`},
		{name: "missing disabled state", mutate: func(f *acceptanceFixture) { delete(f.repository, "disabled") }, want: `missing "disabled"`},
		{name: "missing visibility state", mutate: func(f *acceptanceFixture) { delete(f.repository, "visibility") }, want: `missing "visibility"`},
		{name: "repository identity mismatch", mutate: func(f *acceptanceFixture) { f.repository["full_name"] = "acme/other" }, want: "active public"},
		{name: "forked canary repository", mutate: func(f *acceptanceFixture) { f.repository["fork"] = true }, want: "active public"},
		{name: "private repository", mutate: func(f *acceptanceFixture) { f.repository["private"] = true }, want: "public"},
		{name: "archived repository", mutate: func(f *acceptanceFixture) { f.repository["archived"] = true }, want: "active public"},
		{name: "disabled repository", mutate: func(f *acceptanceFixture) { f.repository["disabled"] = true }, want: "active public"},
		{name: "wrong visibility", mutate: func(f *acceptanceFixture) { f.repository["visibility"] = "internal" }, want: "active public"},
		{name: "wrong run id", mutate: func(f *acceptanceFixture) { f.runs[101]["id"] = int64(999) }, want: "identity"},
		{name: "empty run name", mutate: func(f *acceptanceFixture) { f.runs[101]["name"] = "" }, want: "identity"},
		{name: "wrong run repository", mutate: func(f *acceptanceFixture) {
			fixtureObject(f.runs[101]["repository"])["full_name"] = "acme/other"
		}, want: "identity"},
		{name: "wrong standard event", mutate: func(f *acceptanceFixture) { f.runs[101]["event"] = "push" }, want: "event"},
		{name: "failed run", mutate: func(f *acceptanceFixture) { f.runs[101]["conclusion"] = "failure" }, want: "successful"},
		{name: "cancelled run", mutate: func(f *acceptanceFixture) { f.runs[101]["conclusion"] = "cancelled" }, want: "successful"},
		{name: "in-progress run", mutate: func(f *acceptanceFixture) { f.runs[101]["status"] = "in_progress" }, want: "completed"},
		{name: "zero run attempt", mutate: func(f *acceptanceFixture) { f.runs[101]["run_attempt"] = int64(0) }, want: "attempt"},
		{name: "empty head branch", mutate: func(f *acceptanceFixture) { f.runs[101]["head_branch"] = "" }, want: "head branch"},
		{name: "head branch line break", mutate: func(f *acceptanceFixture) { f.runs[101]["head_branch"] = "main\nother" }, want: "head branch"},
		{name: "invalid head SHA", mutate: func(f *acceptanceFixture) { f.runs[101]["head_sha"] = "main" }, want: "head SHA"},
		{name: "private head repository", mutate: func(f *acceptanceFixture) {
			fixtureObject(f.runs[101]["head_repository"])["private"] = true
		}, want: "public and valid"},
		{name: "invalid head repository identity", mutate: func(f *acceptanceFixture) {
			fixtureObject(f.runs[101]["head_repository"])["full_name"] = "invalid"
		}, want: "public and valid"},
		{name: "fork head is not a fork", mutate: func(f *acceptanceFixture) {
			fixtureObject(f.runs[103]["head_repository"])["fork"] = false
		}, want: "must be a fork"},
		{name: "non-fork head repository mismatch", mutate: func(f *acceptanceFixture) {
			fixtureObject(f.runs[101]["head_repository"])["full_name"] = "acme/other"
		}, want: "does not match the canary"},
		{name: "missing gate", mutate: func(f *acceptanceFixture) { f.jobs[101][0]["name"] = "gate / evidence" }, want: "gate"},
		{name: "failed gate", mutate: func(f *acceptanceFixture) { f.jobs[101][0]["conclusion"] = "failure" }, want: "gate"},
		{name: "gate from other run", mutate: func(f *acceptanceFixture) { f.jobs[101][0]["run_id"] = int64(999) }, want: "gate"},
		{name: "zero gate job id", mutate: func(f *acceptanceFixture) { f.jobs[101][0]["id"] = int64(0) }, want: "gate"},
		{name: "gate from other attempt", mutate: func(f *acceptanceFixture) { f.jobs[101][0]["run_attempt"] = int64(2) }, want: "gate"},
		{name: "gate for other commit", mutate: func(f *acceptanceFixture) { f.jobs[101][0]["head_sha"] = testForkSHA }, want: "gate"},
		{name: "in-progress gate", mutate: func(f *acceptanceFixture) { f.jobs[101][0]["status"] = "in_progress" }, want: "gate"},
		{name: "duplicate gate", mutate: func(f *acceptanceFixture) {
			f.jobs[101] = append(f.jobs[101], f.job(1004, 101, "gate / gate", testConsumerSHA))
		}, want: "exactly one"},
		{name: "stale workflow SHA", mutate: func(f *acceptanceFixture) {
			f.standardCaller = strings.Replace(f.standardCaller, testCandidateSHA, strings.Repeat("d", 40), 1)
		}, want: "candidate SHA"},
		{name: "mutable workflow ref", mutate: func(f *acceptanceFixture) {
			f.standardCaller = strings.Replace(f.standardCaller, testCandidateSHA, "main", 1)
		}, want: "40-character"},
		{name: "empty caller use", mutate: func(f *acceptanceFixture) {
			f.standardCaller = strings.Replace(f.standardCaller, "uses: gomaja/github-ci/.github/workflows/go.yml@"+testCandidateSHA, "uses: ''", 1)
		}, want: "does not invoke"},
		{name: "multiple caller documents", mutate: func(f *acceptanceFixture) { f.standardCaller += "---\n{}\n" }, want: "multiple YAML documents"},
		{name: "same-repository fork", mutate: func(f *acceptanceFixture) { f.pullHeadRepository = testCanary }, want: "different repository"},
		{name: "zero pull request number", mutate: func(f *acceptanceFixture) { setPullFixture(f, func(pull map[string]any) { pull["number"] = int64(0) }) }, want: "associated"},
		{name: "pull head SHA mismatch", mutate: func(f *acceptanceFixture) {
			setPullFixture(f, func(pull map[string]any) { fixtureObject(pull["head"])["sha"] = testConsumerSHA })
		}, want: "associated"},
		{name: "private pull head", mutate: func(f *acceptanceFixture) {
			setPullFixture(f, func(pull map[string]any) { fixtureObject(fixtureObject(pull["head"])["repo"])["private"] = true })
		}, want: "associated"},
		{name: "pull head is not a fork", mutate: func(f *acceptanceFixture) {
			setPullFixture(f, func(pull map[string]any) { fixtureObject(fixtureObject(pull["head"])["repo"])["fork"] = false })
		}, want: "associated"},
		{name: "pull base repository mismatch", mutate: func(f *acceptanceFixture) {
			setPullFixture(f, func(pull map[string]any) {
				fixtureObject(fixtureObject(pull["base"])["repo"])["full_name"] = "acme/other"
			})
		}, want: "associated"},
		{name: "private pull base", mutate: func(f *acceptanceFixture) {
			setPullFixture(f, func(pull map[string]any) { fixtureObject(fixtureObject(pull["base"])["repo"])["private"] = true })
		}, want: "associated"},
		{name: "pull base is a fork", mutate: func(f *acceptanceFixture) {
			setPullFixture(f, func(pull map[string]any) { fixtureObject(fixtureObject(pull["base"])["repo"])["fork"] = true })
		}, want: "associated"},
		{name: "schema 1", mutate: func(f *acceptanceFixture) {
			f.config = strings.Replace(f.config, "schema-version: 2", "schema-version: 1", 1)
		}, want: "schema-version must be 2"},
		{name: "one module", mutate: func(f *acceptanceFixture) {
			f.config = strings.Replace(f.config, "  modules:\n    - path: .\n    - path: tools\n", "  modules:\n    - path: .\n", 1)
		}, want: "at least two modules"},
		{name: "one tag", mutate: func(f *acceptanceFixture) {
			f.config = strings.Replace(f.config, "[canary_a, canary_b]", "[canary_a]", 1)
		}, want: "at least two build tags"},
		{name: "repository-only canary", mutate: func(f *acceptanceFixture) {
			f.config = "schema-version: 2\nprofile: repository-only\ngenerated-paths: [generated]\n"
		}, want: "Go assurance profile"},
		{name: "empty package scope", mutate: func(f *acceptanceFixture) {
			f.config = strings.Replace(f.config, "packages: [./cmd/...]", "packages: []", 1)
		}, want: "packages must not be empty"},
		{name: "missing package scope", mutate: func(f *acceptanceFixture) { f.config = strings.Replace(f.config, "    packages: [./cmd/...]\n", "", 1) }, want: "package scope"},
		{name: "absent generated path", mutate: func(f *acceptanceFixture) {
			f.config = strings.Replace(f.config, "generated-paths:\n  - generated\n", "", 1)
		}, want: "generated path"},
		{name: "untracked generated source", mutate: func(f *acceptanceFixture) {
			f.trees[testCanary] = []map[string]any{}
		}, want: "generated path"},
		{name: "truncated Git tree", mutate: func(f *acceptanceFixture) {
			f.treeTruncated[testCanary] = true
		}, want: "truncated"},
		{name: "duplicate Git tree path", mutate: func(f *acceptanceFixture) {
			f.trees[testCanary] = append(f.trees[testCanary], gitTreeFixture("generated/model.go", "100644", "blob"))
		}, want: "duplicate path"},
		{name: "inconsistent Git tree mode", mutate: func(f *acceptanceFixture) {
			f.trees[testCanary][1]["mode"] = "040000"
		}, want: "inconsistent type"},
		{name: "invalid Git object SHA", mutate: func(f *acceptanceFixture) {
			f.trees[testCanary][1]["sha"] = "main"
		}, want: "invalid object SHA"},
		{name: "traversing generated Git path", mutate: func(f *acceptanceFixture) {
			f.trees[testCanary][1]["path"] = "generated/../model.go"
		}, want: "dot path component"},
		{name: "control character in generated Git path", mutate: func(f *acceptanceFixture) {
			f.trees[testCanary][1]["path"] = "generated/model\n.go"
		}, want: "control character"},
		{name: "untracked module", mutate: func(f *acceptanceFixture) {
			f.status["/repos/"+testCanary+"/contents/tools/go.mod"] = http.StatusNotFound
		}, want: "tracked go.mod"},
		{name: "module content is a directory", mutate: func(f *acceptanceFixture) {
			path := "/repos/" + testCanary + "/contents/tools/go.mod"
			f.raw[path] = `[{"type":"file","encoding":"base64","size":0,"name":"a","path":"tools/go.mod","sha":"dddddddddddddddddddddddddddddddddddddddd","content":""},{"type":"file","encoding":"base64","size":0,"name":"b","path":"tools/other","sha":"dddddddddddddddddddddddddddddddddddddddd","content":""}]`
		}, want: "tracked go.mod"},
		{name: "module content has wrong type", mutate: func(f *acceptanceFixture) {
			path := "/repos/" + testCanary + "/contents/tools/go.mod"
			f.raw[path] = `{"type":"dir","encoding":"base64","size":0,"name":"go.mod","path":"tools/go.mod","sha":"dddddddddddddddddddddddddddddddddddddddd","content":""}`
		}, want: "tracked go.mod"},
		{name: "module content has wrong path", mutate: func(f *acceptanceFixture) {
			path := "/repos/" + testCanary + "/contents/tools/go.mod"
			f.raw[path] = `{"type":"file","encoding":"base64","size":0,"name":"go.mod","path":"other/go.mod","sha":"dddddddddddddddddddddddddddddddddddddddd","content":""}`
		}, want: "tracked go.mod"},
		{name: "default-only package scope", mutate: func(f *acceptanceFixture) { f.config = strings.Replace(f.config, "[./cmd/...]", "[./...]", 1) }, want: "non-default package scope"},
		{name: "missing coverage control", mutate: func(f *acceptanceFixture) {
			f.config = strings.Replace(f.config, "    coverage-packages: [./...]\n", "", 1)
		}, want: "coverage-packages"},
		{name: "missing race control", mutate: func(f *acceptanceFixture) { f.config = strings.Replace(f.config, "    race-parallelism: 1\n", "", 1) }, want: "race-parallelism"},
		{name: "different fork config", mutate: func(f *acceptanceFixture) {
			f.forkConfig = strings.Replace(f.config, "package-parallelism: 3", "package-parallelism: 2", 1)
		}, want: "configuration digest"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAcceptanceFixture()
			test.mutate(fixture)
			_, err := fixture.verify(t)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Verify() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func setPullFixture(fixture *acceptanceFixture, mutate func(map[string]any)) {
	pull := pullRequestFixture(7)
	mutate(pull)
	fixture.pullPages = map[int][]map[string]any{1: {pull}}
}

func TestVerifyFetchesEveryJobsPageAndRejectsPaginationGap(t *testing.T) {
	fixture := newAcceptanceFixture()
	first := make([]map[string]any, 100)
	for index := range first {
		first[index] = fixture.job(10_000+int64(index), 101, "ordinary / "+strconv.Itoa(index), testConsumerSHA)
	}
	fixture.jobPages[101] = map[int][]map[string]any{1: first, 2: fixture.jobs[101]}
	fixture.jobTotals[101] = 101
	if _, err := fixture.verify(t); err != nil {
		t.Fatalf("Verify(paginated) error = %v", err)
	}

	fixture.jobPages[101][2] = []map[string]any{}
	if _, err := fixture.verify(t); err == nil || !strings.Contains(err.Error(), "pagination") {
		t.Fatalf("Verify(gap) error = %v, want pagination error", err)
	}
}

func TestVerifyRejectsAmbiguousForkPullOnLaterPage(t *testing.T) {
	fixture := newAcceptanceFixture()
	first := make([]map[string]any, 0, pullsPerPage)
	for number := 1; number <= pullsPerPage; number++ {
		pull := pullRequestFixture(int64(number))
		fixtureObject(pull["head"])["sha"] = strings.Repeat("d", 40)
		first = append(first, pull)
	}
	fixture.pullPages = map[int][]map[string]any{
		1: first,
		2: {pullRequestFixture(101), pullRequestFixture(102)},
	}
	if _, err := fixture.verify(t); err == nil || !strings.Contains(err.Error(), "multiple matching pull requests") {
		t.Fatalf("Verify() error = %v, want ambiguous pull rejection", err)
	}
}

type acceptanceFixture struct {
	repository         map[string]any
	runs               map[int64]map[string]any
	jobs               map[int64][]map[string]any
	jobPages           map[int64]map[int][]map[string]any
	jobTotals          map[int64]int
	status             map[string]int
	raw                map[string]string
	standardCaller     string
	deepCaller         string
	config             string
	forkConfig         string
	pullHeadRepository string
	pullPages          map[int][]map[string]any
	trees              map[string][]map[string]any
	treeTruncated      map[string]bool
}

func newAcceptanceFixture() *acceptanceFixture {
	fixture := &acceptanceFixture{
		repository: map[string]any{
			"id": int64(1), "name": "go-canary", "full_name": testCanary, "private": false, "fork": false, "archived": false, "disabled": false, "visibility": "public",
			"organization": map[string]any{"login": "acme"}, "custom_properties": map[string]any{"assurance": "strict"},
		},
		runs:               make(map[int64]map[string]any),
		jobs:               make(map[int64][]map[string]any),
		jobPages:           make(map[int64]map[int][]map[string]any),
		jobTotals:          make(map[int64]int),
		status:             make(map[string]int),
		raw:                make(map[string]string),
		pullHeadRepository: testFork,
		trees:              make(map[string][]map[string]any),
		treeTruncated:      make(map[string]bool),
	}
	for _, repository := range []string{testCanary, testFork} {
		fixture.trees[repository] = []map[string]any{
			gitTreeFixture("generated", "040000", "tree"),
			gitTreeFixture("generated/model.go", "100644", "blob"),
		}
	}
	fixture.standardCaller = "name: github-ci\non: [workflow_dispatch]\npermissions:\n  contents: read\njobs:\n  gate:\n    uses: gomaja/github-ci/.github/workflows/go.yml@" + testCandidateSHA + "\n"
	fixture.deepCaller = "name: github-ci-deep\non: [workflow_dispatch]\npermissions:\n  contents: read\njobs:\n  assurance:\n    uses: gomaja/github-ci/.github/workflows/deep.yml@" + testCandidateSHA + "\n"
	fixture.config = `schema-version: 2
profile: go-library
go:
  defaults:
    packages: [./cmd/...]
    module-mode: readonly
    build-tags: [canary_a, canary_b]
    test-timeout: 12m
    package-parallelism: 3
    race-parallelism: 1
    coverage-packages: [./...]
  modules:
    - path: .
    - path: tools
generated-paths:
  - generated
`
	fixture.forkConfig = fixture.config
	fixture.runs[101] = fixture.run(101, "github-ci", "workflow_dispatch", testConsumerSHA, ".github/workflows/github-ci.yml", testCanary)
	fixture.runs[102] = fixture.run(102, "github-ci-deep", "workflow_dispatch", testConsumerSHA, ".github/workflows/github-ci-deep.yml", testCanary)
	fixture.runs[103] = fixture.run(103, "github-ci", "pull_request", testForkSHA, ".github/workflows/github-ci.yml", testFork)
	fixture.jobs[101] = []map[string]any{fixture.job(1001, 101, "gate / gate", testConsumerSHA)}
	fixture.jobs[102] = []map[string]any{fixture.job(1002, 102, "assurance / gate", testConsumerSHA)}
	fixture.jobs[103] = []map[string]any{fixture.job(1003, 103, "gate / gate", testForkSHA)}
	return fixture
}

func (fixture *acceptanceFixture) run(id int64, name, event, sha, path, headRepository string) map[string]any {
	headBranch := "main"
	headDetails := map[string]any{"full_name": headRepository, "private": false, "fork": headRepository != testCanary, "archived": false, "disabled": false}
	if headRepository != testCanary {
		headBranch = "feature"
		headDetails["parent"] = map[string]any{"full_name": testCanary}
		headDetails["source"] = map[string]any{"full_name": testCanary}
	}
	return map[string]any{
		"id": id, "name": name, "event": event, "status": "completed", "conclusion": "success",
		"head_branch": headBranch, "head_sha": sha, "path": path, "run_attempt": 1,
		"repository":      map[string]any{"full_name": testCanary, "private": false, "fork": false, "archived": false, "disabled": false},
		"head_repository": headDetails,
	}
}

func (fixture *acceptanceFixture) job(id, runID int64, name, sha string) map[string]any {
	return map[string]any{"id": id, "run_id": runID, "run_attempt": 1, "name": name, "status": "completed", "conclusion": "success", "head_sha": sha}
}

func (fixture *acceptanceFixture) verify(t *testing.T) (Record, error) {
	t.Helper()
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	return Verify(context.Background(), Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}, Input{
		CandidateSHA: testCandidateSHA, CanaryRepository: testCanary,
		StandardRunID: 101, DeepRunID: 102, ForkRunID: 103,
	})
}

func (fixture *acceptanceFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	if status := fixture.status[path]; status != 0 {
		http.Error(writer, http.StatusText(status), status)
		return
	}
	if raw, exists := fixture.raw[path]; exists {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(raw))
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	switch {
	case path == "/repos/"+testCanary:
		writeFixtureJSON(writer, fixture.repository)
	case strings.HasPrefix(path, "/repos/"+testCanary+"/actions/runs/") && strings.HasSuffix(path, "/jobs"):
		parts := strings.Split(path, "/")
		runID, _ := strconv.ParseInt(parts[6], 10, 64)
		page, _ := strconv.Atoi(request.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		jobs := fixture.jobs[runID]
		if pages := fixture.jobPages[runID]; pages != nil {
			jobs = pages[page]
		}
		total := fixture.jobTotals[runID]
		if total == 0 {
			total = len(fixture.jobs[runID])
		}
		writeFixtureJSON(writer, map[string]any{"total_count": total, "jobs": jobs})
	case strings.HasPrefix(path, "/repos/"+testCanary+"/actions/runs/"):
		parts := strings.Split(path, "/")
		runID, _ := strconv.ParseInt(parts[6], 10, 64)
		writeFixtureJSON(writer, fixture.runs[runID])
	case path == "/repos/"+testCanary+"/pulls":
		fixture.servePullRequests(writer, request)
	case strings.HasPrefix(path, "/repos/") && strings.Contains(path, "/git/trees/"):
		if request.URL.Query().Get("recursive") != "1" {
			http.Error(writer, "recursive tree required", http.StatusBadRequest)
			return
		}
		repository := testCanary
		if strings.HasPrefix(path, "/repos/"+testFork+"/") {
			repository = testFork
		}
		ref := path[strings.LastIndex(path, "/")+1:]
		writeFixtureJSON(writer, map[string]any{
			"sha": ref, "url": "https://example.invalid/tree/" + ref,
			"tree": fixture.trees[repository], "truncated": fixture.treeTruncated[repository],
		})
	case strings.HasPrefix(path, "/repos/") && strings.Contains(path, "/contents/"):
		fixture.serveContent(writer, path)
	default:
		http.Error(writer, "unhandled "+path, http.StatusNotFound)
	}
}

func (fixture *acceptanceFixture) servePullRequests(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Query().Get("state") != "all" || request.URL.Query().Get("head") != "forker:feature" {
		http.Error(writer, "unexpected pull request filter", http.StatusBadRequest)
		return
	}
	if fixture.pullPages != nil {
		page, _ := strconv.Atoi(request.URL.Query().Get("page"))
		writeFixtureJSON(writer, fixture.pullPages[page])
		return
	}
	writeFixtureJSON(writer, []any{map[string]any{
		"number": 7, "state": "open",
		"head": map[string]any{"sha": testForkSHA, "repo": map[string]any{"full_name": fixture.pullHeadRepository, "private": false, "fork": true}},
		"base": map[string]any{"sha": testConsumerSHA, "repo": map[string]any{"full_name": testCanary, "private": false, "fork": false}},
	}})
}

func (fixture *acceptanceFixture) serveContent(writer http.ResponseWriter, path string) {
	repository := testCanary
	if strings.HasPrefix(path, "/repos/"+testFork+"/") {
		repository = testFork
	}
	var content string
	switch {
	case strings.HasSuffix(path, "/contents/go.mod"):
		content = "module example.invalid/canary\n"
	case strings.HasSuffix(path, "/contents/tools/go.mod"):
		content = "module example.invalid/canary/tools\n"
	case strings.HasSuffix(path, "/.github/workflows/github-ci.yml"):
		content = fixture.standardCaller
	case strings.HasSuffix(path, "/.github/workflows/github-ci-deep.yml"):
		content = fixture.deepCaller
	case strings.HasSuffix(path, "/.github/github-ci.yaml") && repository == testFork:
		content = fixture.forkConfig
	case strings.HasSuffix(path, "/.github/github-ci.yaml"):
		content = fixture.config
	default:
		http.Error(writer, "unknown content", http.StatusNotFound)
		return
	}
	writeFixtureJSON(writer, map[string]any{
		"type": "file", "encoding": "base64", "size": len(content), "name": "fixture", "path": path[strings.Index(path, "/contents/")+len("/contents/"):],
		"sha": strings.Repeat("d", 40), "content": base64.StdEncoding.EncodeToString([]byte(content)),
	})
}

func gitTreeFixture(path, mode, objectType string) map[string]any {
	entry := map[string]any{
		"path": path, "mode": mode, "type": objectType,
		"sha": strings.Repeat("d", 40), "url": "https://example.invalid/object",
	}
	if objectType == "blob" {
		entry["size"] = 14
	}
	return entry
}

func writeFixtureJSON(writer http.ResponseWriter, value any) {
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		panic(err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
