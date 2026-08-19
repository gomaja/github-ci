package acceptance

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	// GitHubAPIVersion pins the REST response contract decoded by this package.
	GitHubAPIVersion  = "2026-03-10"
	maxGitHubResponse = 8 << 20
	jobsPerPage       = 100
	maxJobs           = 10_000
	fieldName         = "name"
	jsonNull          = "null"
)

// Client reads immutable public canary evidence from the GitHub REST API.
type Client struct {
	BaseURL    string
	Token      string
	APIVersion string
	HTTP       *http.Client
}

type repository struct {
	FullName   string
	Private    bool
	Archived   bool
	Disabled   bool
	Visibility string
}

type workflowRun struct {
	ID             int64
	Name           string
	Event          string
	Status         string
	Conclusion     string
	HeadSHA        string
	Path           string
	RunAttempt     int64
	Repository     repository
	HeadRepository repository
}

type workflowJob struct {
	ID         int64
	RunID      int64
	RunAttempt int64
	Name       string
	Status     string
	Conclusion string
	HeadSHA    string
}

type jobsPage struct {
	Total int
	Jobs  []workflowJob
}

type pullRequest struct {
	Number int64
	State  string
	Head   struct {
		SHA  string
		Repo repository
	}
	Base struct {
		SHA  string
		Repo repository
	}
}

type contentEntry struct {
	Type     string
	Encoding string
	Size     int64
	Name     string
	Path     string
	SHA      string
	Content  string
}

var repositoryFields = fieldSet(
	"allow_auto_merge", "allow_forking", "allow_merge_commit", "allow_rebase_merge", "allow_squash_merge", "allow_update_branch",
	"archive_url", "archived", "assignees_url", "blobs_url", "branches_url", "clone_url", "collaborators_url", "comments_url",
	"commits_url", "compare_url", "contents_url", "contributors_url", "created_at", "default_branch", "delete_branch_on_merge",
	"deployments_url", "description", "disabled", "downloads_url", "events_url", "fork", "forks", "forks_count", "forks_url",
	"full_name", "git_commits_url", "git_refs_url", "git_tags_url", "git_url", "has_discussions", "has_downloads", "has_issues",
	"has_pages", "has_projects", "has_pull_requests", "has_wiki", "homepage", "hooks_url", "html_url", "id", "is_template",
	"issue_comment_url", "issue_events_url", "issues_url", "keys_url", "labels_url", "language", "languages_url", "license",
	"merge_commit_message", "merge_commit_title", "merges_url", "milestones_url", "mirror_url", fieldName, "network_count", "node_id",
	"notifications_url", "open_issues", "open_issues_count", "owner", "permissions", "private", "pull_request_creation_policy",
	"pulls_url", "pushed_at", "releases_url", "security_and_analysis", "size", "squash_merge_commit_message", "squash_merge_commit_title",
	"ssh_url", "stargazers_count", "stargazers_url", "statuses_url", "subscribers_count", "subscribers_url", "subscription_url",
	"svn_url", "tags_url", "teams_url", "temp_clone_token", "topics", "trees_url", "updated_at", "url", "use_squash_pr_title_as_default",
	"visibility", "watchers", "watchers_count", "web_commit_signoff_required",
)

var workflowRunFields = fieldSet(
	"actor", "artifacts_url", "cancel_url", "check_suite_id", "check_suite_node_id", "check_suite_url", "conclusion", "created_at",
	"display_title", "event", "head_branch", "head_commit", "head_repository", "head_sha", "html_url", "id", "jobs_url", "logs_url",
	fieldName, "node_id", "path", "previous_attempt_url", "pull_requests", "referenced_workflows", "repository", "rerun_url", "run_attempt",
	"run_number", "run_started_at", "status", "triggering_actor", "updated_at", "url", "workflow_id", "workflow_url",
)

var workflowJobFields = fieldSet(
	"check_run_url", "completed_at", "conclusion", "created_at", "head_branch", "head_sha", "html_url", "id", "labels", fieldName,
	"node_id", "run_attempt", "run_id", "run_url", "runner_group_id", "runner_group_name", "runner_id", "runner_name", "started_at",
	"status", "steps", "url", "workflow_name",
)

var contentFields = fieldSet(
	"_links", "content", "download_url", "encoding", "git_url", "html_url", fieldName, "path", "sha", "size", "submodule_git_url",
	"target", "type", "url",
)

func (client Client) getRepository(ctx context.Context, name string) (repository, error) {
	data, err := client.get(ctx, "/repos/"+escapeRepository(name), nil)
	if err != nil {
		return repository{}, err
	}
	fields, err := strictObject(data, repositoryFields)
	if err != nil {
		return repository{}, fmt.Errorf("decode repository: %w", err)
	}
	return decodeRepository(fields)
}

func (client Client) getRun(ctx context.Context, repositoryName string, id int64) (workflowRun, error) {
	data, err := client.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d", escapeRepository(repositoryName), id), nil)
	if err != nil {
		return workflowRun{}, err
	}
	fields, err := strictObject(data, workflowRunFields)
	if err != nil {
		return workflowRun{}, fmt.Errorf("decode workflow run %d: %w", id, err)
	}
	var run workflowRun
	if err := decodeRequired(fields, "id", &run.ID); err != nil {
		return workflowRun{}, err
	}
	for name, destination := range map[string]*string{
		fieldName: &run.Name, "event": &run.Event, "status": &run.Status, "conclusion": &run.Conclusion, "head_sha": &run.HeadSHA, "path": &run.Path,
	} {
		if err := decodeRequired(fields, name, destination); err != nil {
			return workflowRun{}, err
		}
	}
	if err := decodeRequired(fields, "run_attempt", &run.RunAttempt); err != nil {
		return workflowRun{}, err
	}
	for name, destination := range map[string]*repository{"repository": &run.Repository, "head_repository": &run.HeadRepository} {
		raw, exists := fields[name]
		if !exists {
			return workflowRun{}, fmt.Errorf("workflow run is missing %q", name)
		}
		nested, nestedErr := strictObject(raw, repositoryFields)
		if nestedErr != nil {
			return workflowRun{}, fmt.Errorf("decode workflow run %s: %w", name, nestedErr)
		}
		value, decodeErr := decodeRepository(nested)
		if decodeErr != nil {
			return workflowRun{}, decodeErr
		}
		*destination = value
	}
	return run, nil
}

func (client Client) getJobs(ctx context.Context, repositoryName string, run workflowRun) ([]workflowJob, error) {
	var jobs []workflowJob
	seen := make(map[int64]struct{})
	total := -1
	for pageNumber := 1; ; pageNumber++ {
		page, err := client.getJobsPage(ctx, repositoryName, run.ID, pageNumber)
		if err != nil {
			return nil, err
		}
		if page.Total < 0 || page.Total > maxJobs {
			return nil, fmt.Errorf("jobs total_count %d is outside the accepted range", page.Total)
		}
		if total == -1 {
			total = page.Total
		} else if total != page.Total {
			return nil, errors.New("jobs pagination total_count changed between pages")
		}
		if len(page.Jobs) == 0 && len(jobs) < total {
			return nil, errors.New("jobs pagination ended before total_count was reached")
		}
		for _, job := range page.Jobs {
			if _, exists := seen[job.ID]; exists {
				return nil, fmt.Errorf("duplicate job id %d across pagination", job.ID)
			}
			seen[job.ID] = struct{}{}
			jobs = append(jobs, job)
		}
		if len(jobs) == total {
			return jobs, nil
		}
		if len(jobs) > total || len(page.Jobs) != jobsPerPage {
			return nil, errors.New("jobs pagination does not match total_count")
		}
	}
}

func (client Client) getJobsPage(ctx context.Context, repositoryName string, runID int64, pageNumber int) (jobsPage, error) {
	query := url.Values{"filter": {"latest"}, "per_page": {strconv.Itoa(jobsPerPage)}, "page": {strconv.Itoa(pageNumber)}}
	data, err := client.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs", escapeRepository(repositoryName), runID), query)
	if err != nil {
		return jobsPage{}, err
	}
	fields, err := strictObject(data, fieldSet("total_count", "jobs"))
	if err != nil {
		return jobsPage{}, fmt.Errorf("decode jobs for run %d: %w", runID, err)
	}
	var page jobsPage
	if err := decodeRequired(fields, "total_count", &page.Total); err != nil {
		return jobsPage{}, err
	}
	var entries []json.RawMessage
	if err := decodeRequired(fields, "jobs", &entries); err != nil {
		return jobsPage{}, err
	}
	for _, raw := range entries {
		jobFields, fieldErr := strictObject(raw, workflowJobFields)
		if fieldErr != nil {
			return jobsPage{}, fmt.Errorf("decode job: %w", fieldErr)
		}
		job, decodeErr := decodeJob(jobFields)
		if decodeErr != nil {
			return jobsPage{}, decodeErr
		}
		page.Jobs = append(page.Jobs, job)
	}
	return page, nil
}

func (client Client) getPullRequests(ctx context.Context, repositoryName, sha string) ([]pullRequest, error) {
	data, err := client.get(ctx, "/repos/"+escapeRepository(repositoryName)+"/commits/"+url.PathEscape(sha)+"/pulls", nil)
	if err != nil {
		return nil, err
	}
	var raw []json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode pull requests: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode pull requests: %w", err)
	}
	pulls := make([]pullRequest, 0, len(raw))
	for _, item := range raw {
		var wire struct {
			Number int64  `json:"number"`
			State  string `json:"state"`
			Head   struct {
				SHA  string `json:"sha"`
				Repo struct {
					FullName string `json:"full_name"`
					Private  bool   `json:"private"`
					Fork     bool   `json:"fork"`
				} `json:"repo"`
			} `json:"head"`
			Base struct {
				SHA  string `json:"sha"`
				Repo struct {
					FullName string `json:"full_name"`
					Private  bool   `json:"private"`
					Fork     bool   `json:"fork"`
				} `json:"repo"`
			} `json:"base"`
		}
		if err := json.Unmarshal(item, &wire); err != nil {
			return nil, fmt.Errorf("decode pull request: %w", err)
		}
		var pull pullRequest
		pull.Number, pull.State = wire.Number, wire.State
		pull.Head.SHA = wire.Head.SHA
		pull.Head.Repo = repository{FullName: wire.Head.Repo.FullName, Private: wire.Head.Repo.Private}
		pull.Base.SHA = wire.Base.SHA
		pull.Base.Repo = repository{FullName: wire.Base.Repo.FullName, Private: wire.Base.Repo.Private}
		pulls = append(pulls, pull)
	}
	return pulls, nil
}

func (client Client) getContent(ctx context.Context, repositoryName, name, ref string) ([]contentEntry, error) {
	query := url.Values{"ref": {ref}}
	data, err := client.get(ctx, "/repos/"+escapeRepository(repositoryName)+"/contents/"+escapePath(name), query)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		var raw []json.RawMessage
		decoder := json.NewDecoder(bytes.NewReader(data))
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("decode contents %q: %w", name, err)
		}
		if err := requireEOF(decoder); err != nil {
			return nil, err
		}
		entries := make([]contentEntry, 0, len(raw))
		for _, item := range raw {
			entry, decodeErr := decodeContent(item)
			if decodeErr != nil {
				return nil, decodeErr
			}
			entries = append(entries, entry)
		}
		return entries, nil
	}
	entry, err := decodeContent(data)
	if err != nil {
		return nil, err
	}
	return []contentEntry{entry}, nil
}

func (client Client) getFile(ctx context.Context, repositoryName, name, ref string) ([]byte, error) {
	entries, err := client.getContent(ctx, repositoryName, name, ref)
	if err != nil {
		return nil, err
	}
	if len(entries) != 1 || entries[0].Type != contentTypeFile || entries[0].Path != name || entries[0].Encoding != "base64" {
		return nil, fmt.Errorf("contents %q is not the expected base64 file", name)
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(entries[0].Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("decode contents %q: %w", name, err)
	}
	if int64(len(data)) != entries[0].Size {
		return nil, fmt.Errorf("contents %q size does not match decoded data", name)
	}
	return data, nil
}

func (client Client) get(ctx context.Context, endpoint string, query url.Values) ([]byte, error) {
	base, err := client.normalizedBaseURL()
	if err != nil {
		return nil, err
	}
	requestURL := *base
	requestURL.Path = strings.TrimSuffix(base.Path, "/") + endpoint
	requestURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create GitHub request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", client.APIVersion)
	if client.Token != "" {
		request.Header.Set("Authorization", "Bearer "+client.Token)
	}
	httpClient := client.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	copyClient := *httpClient
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("GitHub API redirects are not accepted")
	}
	response, err := copyClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request GitHub API %s: %w", endpoint, err)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxGitHubResponse+1))
	closeErr := response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read GitHub API %s: %w", endpoint, err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close GitHub API %s: %w", endpoint, closeErr)
	}
	if len(data) > maxGitHubResponse {
		return nil, fmt.Errorf("GitHub API %s response exceeds %d byte limit", endpoint, maxGitHubResponse)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API %s returned HTTP %d", endpoint, response.StatusCode)
	}
	return data, nil
}

func (client Client) normalizedBaseURL() (*url.URL, error) {
	baseURL := client.BaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, errors.New("GitHub API base URL must be an absolute HTTPS URL")
	}
	validScheme := base.Scheme == "https" || base.Scheme == "http" && isLoopbackHost(base.Hostname())
	if base.Host == "" || !validScheme || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("GitHub API base URL must be an absolute HTTPS URL")
	}
	if client.APIVersion == "" {
		return nil, errors.New("GitHub API version must not be empty")
	}
	if strings.ContainsAny(client.Token, "\r\n") {
		return nil, errors.New("GitHub token contains a line break")
	}
	return base, nil
}

func decodeRepository(fields map[string]json.RawMessage) (repository, error) {
	var value repository
	if err := decodeRequired(fields, "full_name", &value.FullName); err != nil {
		return repository{}, err
	}
	if raw, exists := fields["visibility"]; exists && string(raw) != jsonNull {
		if err := json.Unmarshal(raw, &value.Visibility); err != nil {
			return repository{}, fmt.Errorf("decode %q: %w", "visibility", err)
		}
	}
	for name, destination := range map[string]*bool{"private": &value.Private, "archived": &value.Archived, "disabled": &value.Disabled} {
		raw, exists := fields[name]
		if !exists {
			continue
		}
		if err := json.Unmarshal(raw, destination); err != nil {
			return repository{}, fmt.Errorf("decode %q: %w", name, err)
		}
	}
	return value, nil
}

func decodeJob(fields map[string]json.RawMessage) (workflowJob, error) {
	var job workflowJob
	for name, destination := range map[string]*int64{"id": &job.ID, "run_id": &job.RunID, "run_attempt": &job.RunAttempt} {
		if err := decodeRequired(fields, name, destination); err != nil {
			return workflowJob{}, err
		}
	}
	for name, destination := range map[string]*string{
		fieldName: &job.Name, "status": &job.Status, "conclusion": &job.Conclusion, "head_sha": &job.HeadSHA,
	} {
		if err := decodeRequired(fields, name, destination); err != nil {
			return workflowJob{}, err
		}
	}
	return job, nil
}

func decodeContent(data []byte) (contentEntry, error) {
	fields, err := strictObject(data, contentFields)
	if err != nil {
		return contentEntry{}, fmt.Errorf("decode contents: %w", err)
	}
	var entry contentEntry
	for name, destination := range map[string]*string{"type": &entry.Type, fieldName: &entry.Name, "path": &entry.Path, "sha": &entry.SHA} {
		if err := decodeRequired(fields, name, destination); err != nil {
			return contentEntry{}, err
		}
	}
	for name, destination := range map[string]*string{"encoding": &entry.Encoding, "content": &entry.Content} {
		if raw, exists := fields[name]; exists && string(raw) != jsonNull {
			if err := json.Unmarshal(raw, destination); err != nil {
				return contentEntry{}, fmt.Errorf("decode %q: %w", name, err)
			}
		}
	}
	if raw, exists := fields["size"]; exists {
		if err := json.Unmarshal(raw, &entry.Size); err != nil {
			return contentEntry{}, fmt.Errorf("decode %q: %w", "size", err)
		}
	}
	return entry, nil
}

func strictObject(data []byte, allowed map[string]struct{}) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("decode JSON object: %w", err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("expected JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("decode JSON field: %w", err)
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("JSON object field is not a string")
		}
		if _, exists := fields[name]; exists {
			return nil, fmt.Errorf("duplicate field %q", name)
		}
		if _, exists := allowed[name]; !exists {
			return nil, fmt.Errorf("unknown field %q", name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("decode field %q: %w", name, err)
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("decode JSON object end: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	return fields, nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains a trailing value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func decodeRequired(fields map[string]json.RawMessage, name string, destination any) error {
	raw, exists := fields[name]
	if !exists || string(raw) == jsonNull {
		return fmt.Errorf("response is missing %q", name)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return fmt.Errorf("decode %q: %w", name, err)
	}
	return nil
}

func fieldSet(names ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}

func escapeRepository(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) != 2 {
		return url.PathEscape(name)
	}
	return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
}

func escapePath(name string) string {
	parts := strings.Split(path.Clean(name), "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/")
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
