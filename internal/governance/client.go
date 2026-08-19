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

const maxResponseBytes = 16_777_216

const defaultBaseURL = "https://api.github.com"

// Client is a bounded GitHub REST client.
type Client struct {
	BaseURL    string
	Token      string
	APIVersion string
	HTTP       *http.Client
	retryWait  func(context.Context, time.Duration) error
}

func (client Client) do(ctx context.Context, method, path string, body []byte, output any) (int, error) {
	endpoint, httpClient, err := client.endpoint(path)
	if err != nil {
		return 0, err
	}
	for attempt := range 3 {
		request, err := client.request(ctx, method, endpoint, body)
		if err != nil {
			return 0, err
		}
		response, err := httpClient.Do(request)
		if err != nil {
			return 0, fmt.Errorf("execute GitHub request: %w", err)
		}
		data, err := readResponse(response)
		if err != nil {
			return response.StatusCode, err
		}
		if shouldRetry(response.StatusCode, method, attempt) {
			if err := client.waitForRetry(ctx, retryDelay(response, attempt)); err != nil {
				return response.StatusCode, err
			}
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return response.StatusCode, fmt.Errorf("GitHub API %s %s returned %d", method, path, response.StatusCode)
		}
		if err := decodeResponse(response.Header.Get("Content-Type"), data, output); err != nil {
			return response.StatusCode, err
		}
		return response.StatusCode, nil
	}
	return 0, errors.New("GitHub request retry budget exhausted")
}

func (client Client) waitForRetry(ctx context.Context, delay time.Duration) error {
	if client.retryWait == nil {
		return waitForRetry(ctx, delay)
	}
	return client.retryWait(ctx, delay)
}

func (client Client) endpoint(path string) (*url.URL, *http.Client, error) {
	baseURL := client.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" && base.Hostname() != "127.0.0.1" && base.Hostname() != "localhost" {
		return nil, nil, errors.New("GitHub API base URL must use HTTPS")
	}
	relative, err := url.Parse(path)
	if err != nil || relative.IsAbs() || !strings.HasPrefix(relative.Path, "/") {
		return nil, nil, fmt.Errorf("invalid GitHub API path %q", path)
	}
	endpoint := base.ResolveReference(relative)
	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return endpoint, httpClient, nil
}

func (client Client) request(ctx context.Context, method string, endpoint *url.URL, body []byte) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create GitHub request: %w", err)
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
	return request, nil
}

func readResponse(response *http.Response) ([]byte, error) {
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.New("read GitHub response")
	}
	if len(data) > maxResponseBytes {
		return nil, errors.New("GitHub response exceeds size limit")
	}
	return data, nil
}

func shouldRetry(status int, method string, attempt int) bool {
	return attempt < 2 && (status == http.StatusTooManyRequests || status >= 500) && retryable(method)
}

func retryDelay(response *http.Response, attempt int) time.Duration {
	delay := time.Duration(attempt+1) * 200 * time.Millisecond
	if value, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && value > 0 && value <= 10 {
		return time.Duration(value) * time.Second
	}
	return delay
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

func decodeResponse(contentType string, data []byte, output any) error {
	if output == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		return fmt.Errorf("GitHub API returned unexpected content type %q", contentType)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode GitHub response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("GitHub response contains trailing JSON")
	}
	return nil
}

func retryable(method string) bool {
	return method == http.MethodGet || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}
