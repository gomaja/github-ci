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
		writeFixtureJSON(writer, map[string]any{"full_name": testCanary, "private": false, "archived": false, "disabled": false, "visibility": "public"})
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", Token: "token-value", HTTP: server.Client()}
	if _, err := client.getRepository(context.Background(), testCanary); err != nil {
		t.Fatalf("getRepository() error = %v", err)
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
