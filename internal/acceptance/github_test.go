package acceptance

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGitHubClientSendsVersionedAuthenticatedRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept") != "application/vnd.github+json" || request.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || request.Header.Get("Authorization") != "Bearer token-value" {
			t.Errorf("headers = %#v", request.Header)
		}
		writeFixtureJSON(writer, map[string]any{"full_name": testCanary, "private": false, "fork": false, "archived": false, "disabled": false, "visibility": "public"})
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
			if _, err := client.getPullRequests(context.Background(), testCanary, testForkSHA); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("getPullRequests() error = %v, want %q", err, test.want)
			}
		})
	}
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
	pulls, err := client.getPullRequests(context.Background(), testCanary, testForkSHA)
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
	if _, err := client.getPullRequests(context.Background(), testCanary, testForkSHA); err == nil || !strings.Contains(err.Error(), "duplicate pull request") {
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
