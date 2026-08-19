package governance

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientHeadersRetryAndDecode(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("Accept = %q", request.Header.Get("Accept"))
		}
		if request.Header.Get("X-GitHub-Api-Version") != "2026-03-10" {
			t.Errorf("X-GitHub-Api-Version = %q", request.Header.Get("X-GitHub-Api-Version"))
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		if requests.Add(1) == 1 {
			http.Error(writer, "retry", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	client := Client{BaseURL: server.URL, Token: "test-token", APIVersion: "2026-03-10", HTTP: server.Client()}
	var response struct {
		OK bool `json:"ok"`
	}
	status, err := client.do(context.Background(), http.MethodGet, "/repos/gomaja/example", nil, &response)
	if err != nil {
		t.Fatalf("do() error = %v", err)
	}
	if status != http.StatusOK || !response.OK || requests.Load() != 2 {
		t.Fatalf("status = %d, response = %+v, requests = %d", status, response, requests.Load())
	}
}

func TestClientRejectsRedirectStatus(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusMultipleChoices)
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
	status, err := client.do(context.Background(), http.MethodGet, "/repos/gomaja/example", nil, nil)
	if err == nil || status != http.StatusMultipleChoices {
		t.Fatalf("do() = (%d, %v), want HTTP 300 error", status, err)
	}
}

func TestClientEndpointPolicyAndDefaultTimeout(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{name: "HTTPS", baseURL: "https://example.com"},
		{name: "IPv4 loopback HTTP", baseURL: "http://127.0.0.1:8080"},
		{name: "localhost HTTP", baseURL: "http://localhost:8080"},
		{name: "remote HTTP", baseURL: "http://example.com", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, httpClient, err := (Client{BaseURL: test.baseURL}).endpoint("/repos/gomaja/example")
			if (err != nil) != test.wantErr {
				t.Fatalf("endpoint() error = %v, wantErr %t", err, test.wantErr)
			}
			if !test.wantErr && httpClient.Timeout != 30*time.Second {
				t.Fatalf("HTTP timeout = %s, want 30s", httpClient.Timeout)
			}
		})
	}
}

func TestClientRequestContentTypeTracksBody(t *testing.T) {
	endpoint, _, err := (Client{BaseURL: "https://example.com"}).endpoint("/repos/gomaja/example")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		body []byte
		want string
	}{
		{name: "empty", body: nil, want: ""},
		{name: "JSON", body: []byte(`{}`), want: "application/json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, requestErr := (Client{}).request(context.Background(), http.MethodPut, endpoint, test.body)
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			if got := request.Header.Get("Content-Type"); got != test.want {
				t.Fatalf("Content-Type = %q, want %q", got, test.want)
			}
		})
	}
}

func TestReadResponseAcceptsExactSizeLimit(t *testing.T) {
	response := &http.Response{Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", maxResponseBytes)))}
	data, err := readResponse(response)
	if err != nil {
		t.Fatalf("readResponse() error = %v", err)
	}
	if len(data) != maxResponseBytes {
		t.Fatalf("readResponse() bytes = %d, want %d", len(data), maxResponseBytes)
	}
}

func TestClientDoesNotRetryPost(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(writer, "failure", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
	if _, err := client.do(context.Background(), http.MethodPost, "/repos/gomaja/example/rulesets", []byte(`{}`), nil); err == nil {
		t.Fatal("do() error = nil, want error")
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", requests.Load())
	}
}

func TestClientRejectsInvalidResponsesAndPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		contentType string
		body        string
		path        string
		want        string
	}{
		{name: "trailing JSON", contentType: "application/json", body: `{} {}`, path: "/repos/gomaja/example", want: "trailing JSON"},
		{name: "malformed JSON", contentType: "application/json", body: `{`, path: "/repos/gomaja/example", want: "decode GitHub response"},
		{name: "unexpected content type", contentType: "text/html", body: `{}`, path: "/repos/gomaja/example", want: "unexpected content type"},
		{name: "absolute path", contentType: "application/json", body: `{}`, path: "https://example.com/escape", want: "invalid GitHub API path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				_, _ = writer.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)
			client := Client{BaseURL: server.URL, Token: "never-print-this", APIVersion: "2026-03-10", HTTP: server.Client()}
			var output map[string]any
			_, err := client.do(context.Background(), http.MethodGet, test.path, nil, &output)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("do() error = %v, want substring %q", err, test.want)
			}
			if strings.Contains(err.Error(), client.Token) {
				t.Fatalf("do() error exposed token: %v", err)
			}
		})
	}
}

func TestClientRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.CopyN(writer, strings.NewReader(strings.Repeat("x", maxResponseBytes+1)), maxResponseBytes+1)
	}))
	t.Cleanup(server.Close)
	client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
	var output any
	_, err := client.do(context.Background(), http.MethodGet, "/repos/gomaja/example", nil, &output)
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("do() error = %v, want size-limit error", err)
	}
}

func TestRetryDelayHonorsBoundedRetryAfter(t *testing.T) {
	response := &http.Response{Header: make(http.Header)}
	response.Header.Set("Retry-After", "2")
	if delay := retryDelay(response, 0); delay != 2*time.Second {
		t.Fatalf("retryDelay(Retry-After) = %s, want 2s", delay)
	}
	response.Header.Set("Retry-After", "10")
	if delay := retryDelay(response, 0); delay != 10*time.Second {
		t.Fatalf("retryDelay(max Retry-After) = %s, want 10s", delay)
	}
	for _, value := range []string{"", "0", "11", "invalid"} {
		response.Header.Set("Retry-After", value)
		if delay := retryDelay(response, 1); delay != 400*time.Millisecond {
			t.Errorf("retryDelay(%q) = %s, want 400ms", value, delay)
		}
	}
}

func FuzzClientResponseDecoding(f *testing.F) {
	for _, seed := range []string{`{}`, `{"enabled":true}`, `{`, `null`, `[]`, "{} {}", strings.Repeat("x", 1024)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(writer, body)
		}))
		t.Cleanup(server.Close)
		client := Client{BaseURL: server.URL, APIVersion: "2026-03-10", HTTP: server.Client()}
		var output map[string]any
		_, _ = client.do(context.Background(), http.MethodGet, "/repos/gomaja/example", nil, &output)
	})
}
