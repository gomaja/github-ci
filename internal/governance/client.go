// Package governance audits and applies GitHub repository desired state.
package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 16 << 20

const defaultBaseURL = "https://api.github.com"

// Client is a bounded GitHub REST client.
type Client struct {
	BaseURL    string
	Token      string
	APIVersion string
	HTTP       *http.Client
}

func (client Client) do(ctx context.Context, method, path string, body []byte, output any) (int, error) {
	baseURL := client.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" && base.Hostname() != "127.0.0.1" && base.Hostname() != "localhost" {
		return 0, errors.New("GitHub API base URL must use HTTPS")
	}
	relative, err := url.Parse(path)
	if err != nil || relative.IsAbs() || !strings.HasPrefix(relative.Path, "/") {
		return 0, fmt.Errorf("invalid GitHub API path %q", path)
	}
	endpoint := base.ResolveReference(relative)
	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	for attempt := 0; attempt < 3; attempt++ {
		request, requestErr := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
		if requestErr != nil {
			return 0, fmt.Errorf("create GitHub request: %w", requestErr)
		}
		request.Header.Set("Accept", "application/vnd.github+json")
		request.Header.Set("X-GitHub-Api-Version", client.APIVersion)
		request.Header.Set("User-Agent", "gomaja-github-ci")
		if client.Token != "" {
			request.Header.Set("Authorization", "Bearer "+client.Token)
		}
		if len(body) != 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		response, responseErr := httpClient.Do(request)
		if responseErr != nil {
			return 0, fmt.Errorf("execute GitHub request: %w", responseErr)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			return response.StatusCode, errors.New("read GitHub response")
		}
		if len(data) > maxResponseBytes {
			return response.StatusCode, errors.New("GitHub response exceeds size limit")
		}
		if (response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500) && retryable(method) {
			if attempt < 2 {
				delay := time.Duration(attempt+1) * 200 * time.Millisecond
				if value, parseErr := strconv.Atoi(response.Header.Get("Retry-After")); parseErr == nil && value > 0 && value <= 10 {
					delay = time.Duration(value) * time.Second
				}
				select {
				case <-ctx.Done():
					return response.StatusCode, ctx.Err()
				case <-time.After(delay):
					continue
				}
			}
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return response.StatusCode, fmt.Errorf("GitHub API %s %s returned %d", method, path, response.StatusCode)
		}
		if output != nil && len(bytes.TrimSpace(data)) != 0 {
			contentType := response.Header.Get("Content-Type")
			if contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
				return response.StatusCode, fmt.Errorf("GitHub API returned unexpected content type %q", contentType)
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			if err := decoder.Decode(output); err != nil {
				return response.StatusCode, fmt.Errorf("decode GitHub response: %w", err)
			}
			var trailing any
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				return response.StatusCode, errors.New("GitHub response contains trailing JSON")
			}
		}
		return response.StatusCode, nil
	}
	return 0, errors.New("GitHub request retry budget exhausted")
}

func retryable(method string) bool {
	return method == http.MethodGet || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}
