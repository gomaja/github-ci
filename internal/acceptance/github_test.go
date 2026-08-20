package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestGitHubClientJobsPaginationChecksEveryBoundary(t *testing.T) {
	tests := []struct {
		name  string
		total int
		jobs  []map[string]any
		want  string
	}{
		{name: "zero total", total: 0},
		{name: "negative total", total: -1, want: "outside the accepted range"},
		{name: "total above maximum", total: maxJobs + 1, want: "outside the accepted range"},
		{name: "exact maximum reaches pagination check", total: maxJobs, jobs: makeJobs(100), want: "pagination ended"},
		{name: "more jobs than total", total: 0, jobs: makeJobs(1), want: "does not match total_count"},
		{name: "short page", total: 2, jobs: makeJobs(1), want: "does not match total_count"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				jobs := test.jobs
				if request.URL.Query().Get("page") != "1" {
					jobs = []map[string]any{}
				}
				if jobs == nil {
					jobs = []map[string]any{}
				}
				writeFixtureJSON(writer, map[string]any{"total_count": test.total, "jobs": jobs})
			}))
			t.Cleanup(server.Close)
			client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion, HTTP: server.Client()}
			jobs, err := client.getJobs(context.Background(), testCanary, workflowRun{ID: 101})
			if test.want == "" {
				if err != nil || len(jobs) != 0 {
					t.Fatalf("getJobs() = %d, %v, want empty success", len(jobs), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("getJobs() error = %v, want %q", err, test.want)
			}
		})
	}
}

func makeJobs(count int) []map[string]any {
	jobs := make([]map[string]any, count)
	for index := range jobs {
		jobs[index] = map[string]any{
			"id": int64(index + 1), "run_id": int64(101), "run_attempt": int64(1),
			"name": fmt.Sprintf("job-%d", index), "status": "completed", "conclusion": "success", "head_sha": testConsumerSHA,
		}
	}
	return jobs
}

func TestGitHubClientPullRequestInputAndPageBoundaries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeFixtureJSON(writer, []map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion, HTTP: server.Client()}
	for _, test := range []struct {
		name   string
		owner  string
		branch string
	}{
		{name: "empty owner", branch: "feature"},
		{name: "empty branch", owner: "forker"},
		{name: "owner line break", owner: "forker\nother", branch: "feature"},
		{name: "branch line break", owner: "forker", branch: "feature\nother"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.getPullRequestsPage(context.Background(), testCanary, test.owner, test.branch, 1); err == nil || !strings.Contains(err.Error(), "must not be empty") {
				t.Fatalf("getPullRequestsPage() error = %v", err)
			}
		})
	}

	overfull := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		pulls := make([]map[string]any, pullsPerPage+1)
		for index := range pulls {
			pulls[index] = pullRequestFixture(int64(index + 1))
		}
		writeFixtureJSON(writer, pulls)
	}))
	t.Cleanup(overfull.Close)
	overfullClient := Client{BaseURL: overfull.URL, APIVersion: GitHubAPIVersion, HTTP: overfull.Client()}
	if _, err := overfullClient.getPullRequests(context.Background(), testCanary, "forker", "feature"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("getPullRequests(overfull) error = %v", err)
	}
}

func TestGitHubClientAcceptsExactPullRequestLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		page, _ := strconv.Atoi(request.URL.Query().Get("page"))
		if page > maxPullRequests/pullsPerPage {
			writeFixtureJSON(writer, []map[string]any{})
			return
		}
		pulls := make([]map[string]any, pullsPerPage)
		first := (page-1)*pullsPerPage + 1
		for index := range pulls {
			pulls[index] = pullRequestFixture(int64(first + index))
		}
		writeFixtureJSON(writer, pulls)
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion, HTTP: server.Client()}
	pulls, err := client.getPullRequests(context.Background(), testCanary, "forker", "feature")
	if err != nil || len(pulls) != maxPullRequests {
		t.Fatalf("getPullRequests() = %d, %v, want %d", len(pulls), err, maxPullRequests)
	}
}

func TestGitHubClientSendsVersionedAuthenticatedRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept") != "application/vnd.github+json" || request.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || request.Header.Get("Authorization") != "Bearer token-value" {
			t.Errorf("headers = %#v", request.Header)
		}
		writeFixtureJSON(writer, map[string]any{
			"full_name": testCanary, "private": false, "fork": false, "archived": false, "disabled": false, "visibility": "public",
			"organization": map[string]any{"login": "acme"}, "custom_properties": map[string]any{"assurance": "strict"},
		})
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", Token: "token-value", HTTP: server.Client()}
	if _, err := client.getRepository(context.Background(), testCanary); err != nil {
		t.Fatalf("getRepository() error = %v", err)
	}
}

func TestGitHubClientRejectsIncompleteOrUnknownPullRequestFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "unknown field", mutate: func(pull map[string]any) { pull["unexpected"] = true }, want: "unknown field"},
		{name: "missing head private", mutate: func(pull map[string]any) {
			delete(fixtureObject(fixtureObject(pull["head"])["repo"]), "private")
		}, want: `missing "private"`},
		{name: "missing head fork", mutate: func(pull map[string]any) {
			delete(fixtureObject(fixtureObject(pull["head"])["repo"]), "fork")
		}, want: `missing "fork"`},
		{name: "missing base private", mutate: func(pull map[string]any) {
			delete(fixtureObject(fixtureObject(pull["base"])["repo"]), "private")
		}, want: `missing "private"`},
		{name: "null head repository", mutate: func(pull map[string]any) {
			fixtureObject(pull["head"])["repo"] = nil
		}, want: "missing repository"},
		{name: "missing head", mutate: func(pull map[string]any) { delete(pull, "head") }, want: `missing "head"`},
		{name: "null head", mutate: func(pull map[string]any) { pull["head"] = nil }, want: `missing "head"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pull := pullRequestFixture(1)
			test.mutate(pull)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writeFixtureJSON(writer, []map[string]any{pull})
			}))
			t.Cleanup(server.Close)
			client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion, HTTP: server.Client()}
			if _, err := client.getPullRequests(context.Background(), testCanary, "forker", "feature"); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("getPullRequests() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestGitTreeEntryCountEnforcesExactBoundary(t *testing.T) {
	if err := validateGitTreeEntryCount(maxGitTreeEntries); err != nil {
		t.Fatalf("validateGitTreeEntryCount(exact) error = %v", err)
	}
	if err := validateGitTreeEntryCount(maxGitTreeEntries + 1); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("validateGitTreeEntryCount(over) error = %v", err)
	}
}

func TestGitHubClientRejectsUntrustedGitTreeResponses(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "unknown response field", mutate: func(tree map[string]any) { tree["unexpected"] = true }, want: "unknown field"},
		{name: "missing response SHA", mutate: func(tree map[string]any) { delete(tree, "sha") }, want: `missing "sha"`},
		{name: "wrong response SHA", mutate: func(tree map[string]any) { tree["sha"] = strings.Repeat("e", 40) }, want: "does not match"},
		{name: "missing truncation state", mutate: func(tree map[string]any) { delete(tree, "truncated") }, want: `missing "truncated"`},
		{name: "truncated", mutate: func(tree map[string]any) { tree["truncated"] = true }, want: "truncated"},
		{name: "null entries", mutate: func(tree map[string]any) { tree["tree"] = nil }, want: `missing "tree"`},
		{name: "unknown entry field", mutate: func(tree map[string]any) {
			firstGitTreeEntry(tree)["unexpected"] = true
		}, want: "unknown field"},
		{name: "missing entry mode", mutate: func(tree map[string]any) {
			delete(firstGitTreeEntry(tree), "mode")
		}, want: `missing "mode"`},
		{name: "negative entry size", mutate: func(tree map[string]any) {
			firstGitTreeEntry(tree)["size"] = -1
		}, want: "must not be negative"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := map[string]any{
				"sha": testConsumerSHA, "truncated": false,
				"tree": []map[string]any{gitTreeFixture("generated/model.go", "100644", "blob")},
				"url":  "https://example.invalid/tree",
			}
			test.mutate(response)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writeFixtureJSON(writer, response)
			}))
			t.Cleanup(server.Close)
			client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion, HTTP: server.Client()}
			if _, err := client.getTree(context.Background(), testCanary, testConsumerSHA); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("getTree() error = %v, want %q", err, test.want)
			}
		})
	}
}

func firstGitTreeEntry(tree map[string]any) map[string]any {
	entries, ok := tree["tree"].([]map[string]any)
	if !ok || len(entries) == 0 {
		panic("Git tree fixture is missing entries")
	}
	return entries[0]
}

func TestGitHubClientRejectsRedirectsOversizedResponsesAndUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		client  func(string, *http.Client) Client
		want    string
	}{
		{
			name: "redirect", handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				http.Redirect(writer, request, "/other", http.StatusFound)
			}),
			client: func(base string, httpClient *http.Client) Client {
				return Client{BaseURL: base, APIVersion: "2026-03-10", HTTP: httpClient}
			}, want: "redirect",
		},
		{
			name: "oversized", handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(writer, strings.Repeat("x", maxGitHubResponse+1))
			}),
			client: func(base string, httpClient *http.Client) Client {
				return Client{BaseURL: base, APIVersion: "2026-03-10", HTTP: httpClient}
			}, want: "exceeds",
		},
		{
			name: "token newline", handler: http.NotFoundHandler(),
			client: func(base string, httpClient *http.Client) Client {
				return Client{BaseURL: base, APIVersion: "2026-03-10", Token: "secret\nheader", HTTP: httpClient}
			}, want: "line break",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			t.Cleanup(server.Close)
			client := test.client(server.URL, server.Client())
			if _, err := client.getRepository(context.Background(), testCanary); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("getRepository() error = %v, want %q", err, test.want)
			}
		})
	}

	client := Client{BaseURL: "http://example.com", APIVersion: "2026-03-10"}
	if _, err := client.getRepository(context.Background(), testCanary); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("getRepository(insecure) error = %v", err)
	}
}

func TestGitHubClientContentDecodingRejectsEveryMalformedShape(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "empty response", body: "", want: "decode contents"},
		{name: "malformed array", body: "[", want: "decode contents"},
		{name: "trailing array value", body: "[]{}", want: "trailing"},
		{name: "invalid array entry", body: `[{"type":"file"}]`, want: "missing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)
			client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion, HTTP: server.Client()}
			if _, err := client.getContent(context.Background(), testCanary, "path", testConsumerSHA); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("getContent() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestGitHubClientFileDecodingRequiresEveryIdentityField(t *testing.T) {
	valid := map[string]any{
		"type": "file", "encoding": "base64", "size": 0, "name": "config", "path": "config", "sha": testConsumerSHA, "content": "",
	}
	tests := []struct {
		name   string
		mutate func(map[string]any) any
	}{
		{name: "multiple entries", mutate: func(entry map[string]any) any { return []map[string]any{entry, entry} }},
		{name: "wrong type", mutate: func(entry map[string]any) any { entry["type"] = "dir"; return entry }},
		{name: "wrong path", mutate: func(entry map[string]any) any { entry["path"] = "other"; return entry }},
		{name: "wrong encoding", mutate: func(entry map[string]any) any { entry["encoding"] = "utf-8"; return entry }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := make(map[string]any, len(valid))
			maps.Copy(entry, valid)
			body := test.mutate(entry)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writeFixtureJSON(writer, body) }))
			t.Cleanup(server.Close)
			client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion, HTTP: server.Client()}
			if _, err := client.getFile(context.Background(), testCanary, "config", testConsumerSHA); err == nil || !strings.Contains(err.Error(), "not the expected base64 file") {
				t.Fatalf("getFile() error = %v", err)
			}
		})
	}
}

func TestGitHubClientAcceptsExactResponseByteLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(bytes.Repeat([]byte{' '}, maxGitHubResponse))
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion, HTTP: server.Client()}
	data, err := client.get(context.Background(), "", nil)
	if err != nil || len(data) != maxGitHubResponse {
		t.Fatalf("get() = %d bytes, %v, want exact limit", len(data), err)
	}
}

func TestGitHubClientUsesBoundedDefaultHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion}
	if _, err := client.get(context.Background(), "", nil); err != nil {
		t.Fatalf("get() with default HTTP client error = %v", err)
	}
}

func TestGitHubDecodersAcceptOptionalAndBoundaryValues(t *testing.T) {
	for _, visibility := range []string{"", jsonNull, `"public"`} {
		data := `{"full_name":"acme/repository","private":false,"fork":false`
		if visibility != "" {
			data += `,"visibility":` + visibility
		}
		data += `}`
		fields, err := strictObject([]byte(data), repositoryFields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRepository(fields); err != nil {
			t.Fatalf("decodeRepository(%q) error = %v", visibility, err)
		}
	}

	content, err := decodeContent([]byte(`{"type":"dir","name":"generated","path":"generated","sha":"dddddddddddddddddddddddddddddddddddddddd"}`))
	if err != nil || content.Encoding != "" || content.Content != "" || content.Size != 0 {
		t.Fatalf("decodeContent(optional fields) = %#v, %v", content, err)
	}
	entry, err := decodeGitTreeEntry([]byte(`{"path":"empty","mode":"100644","type":"blob","sha":"dddddddddddddddddddddddddddddddddddddddd","size":0}`))
	if err != nil || entry.Size == nil || *entry.Size != 0 {
		t.Fatalf("decodeGitTreeEntry(zero size) = %#v, %v", entry, err)
	}
}

func TestStrictJSONHelpersRejectEachInvalidEnvelope(t *testing.T) {
	for _, data := range []string{"[]", `"value"`, "null"} {
		if _, err := strictObject([]byte(data), map[string]struct{}{}); err == nil || !strings.Contains(err.Error(), "expected JSON object") {
			t.Fatalf("strictObject(%s) error = %v", data, err)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(`{}{} `)))
	var first any
	if err := decoder.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := requireEOF(decoder); err == nil || err.Error() != "JSON contains a trailing value" {
		t.Fatalf("requireEOF() error = %v", err)
	}
}

func fixtureObject(value any) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		panic("acceptance fixture value is not an object")
	}
	return object
}

func TestGitHubClientFetchesEveryPullRequestPage(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/repos/"+testCanary+"/pulls" || request.URL.Query().Get("state") != "all" || request.URL.Query().Get("head") != "forker:feature" {
			t.Errorf("pull request query = %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		if request.URL.Query().Get("per_page") != "100" {
			t.Errorf("per_page = %q, want 100", request.URL.Query().Get("per_page"))
		}
		page := request.URL.Query().Get("page")
		var pulls []map[string]any
		switch page {
		case "1":
			for number := 1; number <= 100; number++ {
				pulls = append(pulls, pullRequestFixture(int64(number)))
			}
		case "2":
			pulls = append(pulls, pullRequestFixture(101))
		default:
			t.Errorf("unexpected page %q", page)
		}
		writeFixtureJSON(writer, pulls)
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion, HTTP: server.Client()}
	pulls, err := client.getPullRequests(context.Background(), testCanary, "forker", "feature")
	if err != nil {
		t.Fatalf("getPullRequests() error = %v", err)
	}
	if len(pulls) != 101 || requests != 2 {
		t.Fatalf("getPullRequests() returned %d pulls in %d requests, want 101 in 2", len(pulls), requests)
	}
}

func TestGitHubClientRejectsDuplicatePullRequestAcrossPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		page := request.URL.Query().Get("page")
		pulls := make([]map[string]any, 0, pullsPerPage)
		if page == "1" {
			for number := 1; number <= pullsPerPage; number++ {
				pulls = append(pulls, pullRequestFixture(int64(number)))
			}
		} else {
			pulls = append(pulls, pullRequestFixture(pullsPerPage))
		}
		writeFixtureJSON(writer, pulls)
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: GitHubAPIVersion, HTTP: server.Client()}
	if _, err := client.getPullRequests(context.Background(), testCanary, "forker", "feature"); err == nil || !strings.Contains(err.Error(), "duplicate pull request") {
		t.Fatalf("getPullRequests() error = %v, want duplicate rejection", err)
	}
}

func pullRequestFixture(number int64) map[string]any {
	return map[string]any{
		"number": number,
		"state":  "open",
		"head": map[string]any{
			"sha":  testForkSHA,
			"repo": map[string]any{"full_name": testFork, "private": false, "fork": true},
		},
		"base": map[string]any{
			"sha":  testConsumerSHA,
			"repo": map[string]any{"full_name": testCanary, "private": false, "fork": false},
		},
	}
}
