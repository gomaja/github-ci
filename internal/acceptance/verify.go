package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/pathpolicy"
	"gopkg.in/yaml.v3"
)

const (
	consumerConfigPath  = ".github/github-ci.yaml"
	maxGeneratedEntries = 10_000
)

// Input identifies the candidate and the three external canary runs to verify.
type Input struct {
	CandidateSHA     string
	CanaryRepository string
	StandardRunID    int64
	DeepRunID        int64
	ForkRunID        int64
}

type scenario struct {
	kind         RunKind
	runID        int64
	workflowPath string
	reusablePath string
	jobKey       string
	gateJob      string
	event        string
}

// Verify proves successful standard, deep, and untrusted-fork adoption at one candidate commit.
func Verify(ctx context.Context, client Client, input Input) (Record, error) {
	if ctx == nil {
		return Record{}, errors.New("context must not be nil")
	}
	if err := validateInput(input); err != nil {
		return Record{}, err
	}
	repositoryValue, err := client.getRepository(ctx, input.CanaryRepository)
	if err != nil {
		return Record{}, err
	}
	if repositoryValue.FullName != input.CanaryRepository || repositoryValue.Private || repositoryValue.Fork || repositoryValue.Visibility != "public" || repositoryValue.Archived || repositoryValue.Disabled {
		return Record{}, errors.New("canary repository must be an active public repository")
	}

	scenarios := []scenario{
		{kind: RunStandard, runID: input.StandardRunID, workflowPath: standardCallerPath, reusablePath: ".github/workflows/go.yml", jobKey: "gate", gateJob: standardGateName, event: manualDispatchEvent},
		{kind: RunDeep, runID: input.DeepRunID, workflowPath: scheduledCallerPath, reusablePath: ".github/workflows/deep.yml", jobKey: "assurance", gateJob: "assurance / gate", event: manualDispatchEvent},
		{kind: RunFork, runID: input.ForkRunID, workflowPath: standardCallerPath, reusablePath: ".github/workflows/go.yml", jobKey: "gate", gateJob: standardGateName, event: "pull_request"},
	}
	record := Record{SchemaVersion: SchemaVersion, CandidateSHA: input.CandidateSHA, CanaryRepository: input.CanaryRepository}
	var configDigest string
	for _, expected := range scenarios {
		runRecord, digest, verifyErr := verifyScenario(ctx, client, input, expected)
		if verifyErr != nil {
			return Record{}, fmt.Errorf("verify %s run: %w", expected.kind, verifyErr)
		}
		if configDigest == "" {
			configDigest = digest
		} else if digest != configDigest {
			return Record{}, fmt.Errorf("%s run configuration digest %s does not match %s", expected.kind, digest, configDigest)
		}
		record.Runs = append(record.Runs, runRecord)
	}
	record.ConfigSHA256 = configDigest
	if err := ValidateRecord(record, input.CandidateSHA); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateInput(input Input) error {
	if !gitSHAPattern.MatchString(input.CandidateSHA) {
		return errors.New("candidate SHA must be a 40-character lowercase hexadecimal commit SHA")
	}
	if !repositoryPattern.MatchString(input.CanaryRepository) || input.CanaryRepository == "gomaja/github-ci" {
		return errors.New("canary repository must identify a different owner/repository")
	}
	if input.StandardRunID <= 0 || input.DeepRunID <= 0 || input.ForkRunID <= 0 {
		return errors.New("all acceptance run IDs must be positive")
	}
	if input.StandardRunID == input.DeepRunID || input.StandardRunID == input.ForkRunID || input.DeepRunID == input.ForkRunID {
		return errors.New("acceptance run IDs must be distinct")
	}
	return nil
}

func verifyScenario(ctx context.Context, client Client, input Input, expected scenario) (RunRecord, string, error) {
	run, err := client.getRun(ctx, input.CanaryRepository, expected.runID)
	if err != nil {
		return RunRecord{}, "", err
	}
	if err := validateWorkflowRun(run, input, expected); err != nil {
		return RunRecord{}, "", err
	}

	jobs, err := client.getJobs(ctx, input.CanaryRepository, run)
	if err != nil {
		return RunRecord{}, "", err
	}
	if err := verifyGateJob(run, jobs, expected.gateJob); err != nil {
		return RunRecord{}, "", err
	}
	caller, err := client.getFile(ctx, run.HeadRepository.FullName, expected.workflowPath, run.HeadSHA)
	if err != nil {
		return RunRecord{}, "", fmt.Errorf("read caller workflow: %w", err)
	}
	if err := verifyCaller(caller, expected.jobKey, expected.reusablePath, input.CandidateSHA); err != nil {
		return RunRecord{}, "", err
	}
	configuration, err := client.getFile(ctx, run.HeadRepository.FullName, consumerConfigPath, run.HeadSHA)
	if err != nil {
		return RunRecord{}, "", fmt.Errorf("read consumer configuration: %w", err)
	}
	consumer, err := config.DecodeConsumer(bytes.NewReader(configuration))
	if err != nil {
		return RunRecord{}, "", fmt.Errorf("decode consumer configuration: %w", err)
	}
	if err := verifyCanaryConfiguration(ctx, client, run.HeadRepository.FullName, run.HeadSHA, consumer); err != nil {
		return RunRecord{}, "", err
	}
	digest := sha256.Sum256(configuration)
	pullNumber := int64(0)
	if expected.kind == RunFork {
		pullNumber, err = verifyForkPullRequest(ctx, client, input.CanaryRepository, run)
		if err != nil {
			return RunRecord{}, "", err
		}
	}
	return RunRecord{
		Kind: expected.kind, ID: run.ID, Repository: run.Repository.FullName, HeadRepository: run.HeadRepository.FullName,
		Event: run.Event, HeadSHA: run.HeadSHA, WorkflowPath: run.Path, WorkflowSHA: input.CandidateSHA, GateJob: expected.gateJob,
		PullRequest: pullNumber,
	}, hex.EncodeToString(digest[:]), nil
}

func validateWorkflowRun(run workflowRun, input Input, expected scenario) error {
	if run.ID != expected.runID || run.Name == "" || run.Repository.FullName != input.CanaryRepository {
		return errors.New("workflow run identity does not match the requested canary")
	}
	if run.Event != expected.event {
		return fmt.Errorf("workflow run event %q does not match %q", run.Event, expected.event)
	}
	if run.Status != "completed" {
		return fmt.Errorf("workflow run is not completed: %q", run.Status)
	}
	if run.Conclusion != "success" {
		return fmt.Errorf("workflow run is not successful: %q", run.Conclusion)
	}
	if run.Path != expected.workflowPath {
		return fmt.Errorf("workflow run path %q does not match %q", run.Path, expected.workflowPath)
	}
	if run.RunAttempt <= 0 || run.HeadBranch == "" || strings.ContainsAny(run.HeadBranch, "\r\n") || !gitSHAPattern.MatchString(run.HeadSHA) {
		return errors.New("workflow run attempt, head branch, or head SHA is invalid")
	}
	if run.HeadRepository.Private || !repositoryPattern.MatchString(run.HeadRepository.FullName) {
		return errors.New("workflow run head repository must be public and valid")
	}
	if expected.kind == RunFork {
		if run.HeadRepository.FullName == input.CanaryRepository {
			return errors.New("fork run head must come from a different repository")
		}
		if !run.HeadRepository.Fork {
			return errors.New("fork run head repository must be a fork")
		}
	} else if run.HeadRepository.FullName != input.CanaryRepository {
		return errors.New("non-fork run head repository does not match the canary")
	}
	return nil
}

func verifyGateJob(run workflowRun, jobs []workflowJob, expectedName string) error {
	matches := 0
	for _, job := range jobs {
		if job.Name != expectedName {
			continue
		}
		matches++
		if job.ID <= 0 || job.RunID != run.ID || job.RunAttempt != run.RunAttempt || job.HeadSHA != run.HeadSHA || job.Status != "completed" || job.Conclusion != "success" {
			return fmt.Errorf("gate job %q is not successful for the verified run attempt", expectedName)
		}
	}
	if matches != 1 {
		return fmt.Errorf("expected exactly one successful gate job %q, found %d", expectedName, matches)
	}
	return nil
}

func verifyCaller(data []byte, jobKey, reusablePath, candidateSHA string) error {
	var caller struct {
		Jobs map[string]struct {
			Uses string `yaml:"uses"`
		} `yaml:"jobs"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&caller); err != nil {
		return fmt.Errorf("decode caller workflow: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("caller workflow contains multiple YAML documents")
		}
		return fmt.Errorf("decode trailing caller workflow: %w", err)
	}
	job, exists := caller.Jobs[jobKey]
	if !exists || job.Uses == "" {
		return fmt.Errorf("caller workflow job %q does not invoke a reusable workflow", jobKey)
	}
	prefix := "gomaja/github-ci/" + reusablePath + "@"
	if !strings.HasPrefix(job.Uses, prefix) {
		return fmt.Errorf("caller workflow job %q does not invoke %s", jobKey, reusablePath)
	}
	reference := strings.TrimPrefix(job.Uses, prefix)
	if !gitSHAPattern.MatchString(reference) {
		return errors.New("caller workflow reference must be a 40-character lowercase hexadecimal commit SHA")
	}
	if reference != candidateSHA {
		return errors.New("caller workflow does not reference the candidate SHA")
	}
	return nil
}

func verifyCanaryConfiguration(ctx context.Context, client Client, repositoryName, ref string, consumer config.Consumer) error {
	if err := validateCanaryConsumer(consumer); err != nil {
		return err
	}
	if err := verifyCanaryModules(ctx, client, repositoryName, ref, consumer.Go.Modules); err != nil {
		return err
	}
	return verifyCanaryGeneratedPaths(ctx, client, repositoryName, ref, consumer.GeneratedPaths)
}

func validateCanaryConsumer(consumer config.Consumer) error {
	if consumer.SchemaVersion != 2 {
		return errors.New("canary schema-version must be 2")
	}
	if consumer.Profile != config.ProfileGoStrict && consumer.Profile != config.ProfileGoLibrary {
		return errors.New("canary must select a Go assurance profile")
	}
	if consumer.Go == nil || len(consumer.Go.Modules) < 2 {
		return errors.New("canary must configure at least two modules")
	}
	settings := consumer.Go.Defaults
	if settings.BuildTags == nil || len(*settings.BuildTags) < 2 {
		return errors.New("canary must configure at least two build tags")
	}
	if settings.Packages == nil || len(*settings.Packages) == 0 || (len(*settings.Packages) == 1 && (*settings.Packages)[0] == "./...") {
		return errors.New("canary must configure an explicit non-default package scope")
	}
	if settings.ModuleMode == nil {
		return errors.New("canary must configure module-mode")
	}
	if settings.TestTimeout == nil {
		return errors.New("canary must configure test-timeout")
	}
	if settings.PackageParallelism == nil {
		return errors.New("canary must configure package-parallelism")
	}
	if settings.RaceParallelism == nil {
		return errors.New("canary must configure race-parallelism")
	}
	if settings.CoveragePackages == nil {
		return errors.New("canary must configure coverage-packages")
	}
	if len(consumer.GeneratedPaths) == 0 {
		return errors.New("canary must configure at least one generated path")
	}
	return nil
}

func verifyCanaryModules(ctx context.Context, client Client, repositoryName, ref string, modules []config.GoModule) error {
	for _, module := range modules {
		moduleFile := "go.mod"
		if module.Path != "." {
			moduleFile = path.Join(string(module.Path), "go.mod")
		}
		entries, err := client.getContent(ctx, repositoryName, moduleFile, ref)
		if err != nil || len(entries) != 1 || entries[0].Type != contentTypeFile || entries[0].Path != moduleFile {
			return fmt.Errorf("canary module %q does not contain a tracked go.mod", module.Path)
		}
	}
	return nil
}

func verifyCanaryGeneratedPaths(ctx context.Context, client Client, repositoryName, ref string, generatedPaths []string) error {
	generatedGo := false
	entryCount := 0
	for _, generatedPath := range generatedPaths {
		found, err := findGeneratedGo(ctx, client, repositoryName, ref, generatedPath, generatedPath, make(map[string]struct{}), &entryCount)
		if err != nil {
			return fmt.Errorf("read generated path %q: %w", generatedPath, err)
		}
		generatedGo = generatedGo || found
	}
	if !generatedGo {
		return errors.New("canary generated path must contain a tracked Go source file")
	}
	return nil
}

func findGeneratedGo(ctx context.Context, client Client, repositoryName, ref, root, current string, seen map[string]struct{}, entryCount *int) (bool, error) {
	if _, exists := seen[current]; exists {
		return false, fmt.Errorf("generated directory %q was visited more than once", current)
	}
	seen[current] = struct{}{}
	entries, err := client.getContent(ctx, repositoryName, current, ref)
	if err != nil {
		return false, err
	}
	found := false
	singleFile := len(entries) == 1 && entries[0].Type == contentTypeFile && entries[0].Path == current
	for _, entry := range entries {
		(*entryCount)++
		if *entryCount > maxGeneratedEntries {
			return false, fmt.Errorf("generated paths exceed %d entries", maxGeneratedEntries)
		}
		if err := pathpolicy.Validate("generated API path", entry.Path); err != nil {
			return false, err
		}
		if entry.Name != path.Base(entry.Path) {
			return false, fmt.Errorf("generated API path %q has mismatched name %q", entry.Path, entry.Name)
		}
		if root != "." && entry.Path != root && !strings.HasPrefix(entry.Path, root+"/") {
			return false, fmt.Errorf("generated API path %q escapes %q", entry.Path, root)
		}
		if !singleFile && path.Dir(entry.Path) != current {
			return false, fmt.Errorf("generated API path %q is not a direct child of %q", entry.Path, current)
		}
		switch entry.Type {
		case contentTypeFile:
			found = found || strings.HasSuffix(entry.Path, ".go")
		case "dir":
			nested, nestedErr := findGeneratedGo(ctx, client, repositoryName, ref, root, entry.Path, seen, entryCount)
			if nestedErr != nil {
				return false, nestedErr
			}
			found = found || nested
		default:
			return false, fmt.Errorf("generated API path %q has unsupported type %q", entry.Path, entry.Type)
		}
	}
	return found, nil
}

func verifyForkPullRequest(ctx context.Context, client Client, baseRepository string, run workflowRun) (int64, error) {
	headOwner, _, ok := strings.Cut(run.HeadRepository.FullName, "/")
	if !ok || headOwner == "" {
		return 0, errors.New("fork run head repository owner is invalid")
	}
	pulls, err := client.getPullRequests(ctx, baseRepository, headOwner, run.HeadBranch)
	if err != nil {
		return 0, err
	}
	var match int64
	for _, pull := range pulls {
		if pull.Number <= 0 || pull.Head.SHA != run.HeadSHA || pull.Head.Repo.FullName != run.HeadRepository.FullName || pull.Head.Repo.Private || !pull.Head.Repo.Fork || pull.Base.Repo.FullName != baseRepository || pull.Base.Repo.Private || pull.Base.Repo.Fork {
			continue
		}
		if match != 0 {
			return 0, errors.New("fork run commit is associated with multiple matching pull requests")
		}
		match = pull.Number
	}
	if match == 0 {
		return 0, errors.New("fork run is not associated with a public pull request from a different repository")
	}
	return match, nil
}
