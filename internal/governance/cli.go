package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/securefs"
)

const maxPlanBytes = 16_777_216

// RunCLI executes the governance command-line interface.
func RunCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeCLIError(stderr, errors.New("usage: github-ci-govern <audit|plan|apply|verify|render-callers>"))
		return 2
	}
	switch args[0] {
	case "audit", "verify":
		return runAuditCLI(ctx, args[0], args[1:], stdout, stderr)
	case "plan":
		return runPlanCLI(ctx, args[1:], stdout, stderr)
	case "apply":
		return runApplyCLI(ctx, args[1:], stdout, stderr)
	case "render-callers":
		return runRenderCallersCLI(args[1:], stderr)
	default:
		writeCLIError(stderr, fmt.Errorf("unknown command %q", args[0]))
		return 2
	}
}

func runAuditCLI(ctx context.Context, name string, args []string, stdout, stderr io.Writer) int {
	flags := newGovernanceFlags(name, stderr)
	manifestPath := flags.String("manifest", "governance/gomaja.yaml", "governance manifest")
	baseURL := flags.String("base-url", defaultBaseURL, "GitHub API base URL")
	repository := flags.String("repository", "", "govern one repository")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	manifest, err := readManifest(*manifestPath)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	manifest, err = scopeGovernance(manifest, *repository)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	plan, err := BuildPlan(ctx, newAPIClient(*baseURL, manifest.APIVersion), manifest)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if err := writePlan(stdout, plan); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if len(plan.Operations) != 0 {
		return 1
	}
	return 0
}

func runPlanCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := newGovernanceFlags("plan", stderr)
	manifestPath := flags.String("manifest", "governance/gomaja.yaml", "governance manifest")
	baseURL := flags.String("base-url", defaultBaseURL, "GitHub API base URL")
	output := flags.String("output", "", "plan output path; omit to use stdout")
	repository := flags.String("repository", "", "govern one repository")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	manifest, err := readManifest(*manifestPath)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	manifest, err = scopeGovernance(manifest, *repository)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	plan, err := BuildPlan(ctx, newAPIClient(*baseURL, manifest.APIVersion), manifest)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if *output == "" {
		if err := writePlan(stdout, plan); err != nil {
			writeCLIError(stderr, err)
			return 2
		}
		return 0
	}
	data, err := marshalPlan(plan)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if err := writeFileAtomic(*output, data, 0o644); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	return 0
}

func runApplyCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := newGovernanceFlags("apply", stderr)
	manifestPath := flags.String("manifest", "governance/gomaja.yaml", "governance manifest")
	baseURL := flags.String("base-url", defaultBaseURL, "GitHub API base URL")
	planPath := flags.String("plan", "", "approved plan path")
	confirm := flags.String("confirm", "", "exact approved plan id")
	repository := flags.String("repository", "", "govern one repository")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *planPath == "" || *confirm == "" {
		writeCLIError(stderr, errors.New("--plan and --confirm are required"))
		return 2
	}
	manifest, err := readManifest(*manifestPath)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	manifest, err = scopeGovernance(manifest, *repository)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	plan, err := readPlan(*planPath)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	client := newAPIClient(*baseURL, manifest.APIVersion)
	if err := Apply(ctx, client, manifest, plan, *confirm); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	verified, err := BuildPlan(ctx, client, manifest)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if err := writePlan(stdout, verified); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	return 0
}

func runRenderCallersCLI(args []string, stderr io.Writer) int {
	flags := newGovernanceFlags("render-callers", stderr)
	manifestPath := flags.String("manifest", "governance/gomaja.yaml", "governance manifest")
	output := flags.String("output", "", "caller output directory")
	workflowSHA := flags.String("workflow-sha", "", "approved reusable workflow commit SHA")
	repository := flags.String("repository", "", "render one repository")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	manifest, err := readManifest(*manifestPath)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if err := RenderCallers(manifest, *output, *workflowSHA, *repository); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	return 0
}

func newGovernanceFlags(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func newAPIClient(baseURL, apiVersion string) Client {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	return Client{BaseURL: baseURL, Token: token, APIVersion: apiVersion}
}

func scopeGovernance(manifest config.Governance, repository string) (config.Governance, error) {
	if repository == "" {
		return manifest, nil
	}
	for _, candidate := range manifest.Repositories {
		if candidate.Name == repository {
			manifest.Repositories = []config.Repository{candidate}
			return manifest, nil
		}
	}
	return config.Governance{}, fmt.Errorf("repository %q is not present in the governance manifest", repository)
}

func readManifest(name string) (config.Governance, error) {
	file, err := securefs.Open(name)
	if err != nil {
		return config.Governance{}, fmt.Errorf("open governance manifest: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxPlanBytes+1))
	if err != nil {
		return config.Governance{}, fmt.Errorf("read governance manifest: %w", err)
	}
	if exceedsPlanSize(len(data)) {
		return config.Governance{}, errors.New("governance manifest exceeds size limit")
	}
	return config.DecodeGovernance(bytes.NewReader(data))
}

func readPlan(name string) (Plan, error) {
	data, err := securefs.ReadFile(name)
	if err != nil {
		return Plan{}, fmt.Errorf("read governance plan: %w", err)
	}
	if exceedsPlanSize(len(data)) {
		return Plan{}, errors.New("governance plan exceeds size limit")
	}
	return decodePlan(data)
}

func exceedsPlanSize(size int) bool {
	return size > maxPlanBytes
}

func decodePlan(data []byte) (Plan, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("decode governance plan: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Plan{}, errors.New("governance plan contains trailing JSON")
	}
	identity := plan
	identity.ID = ""
	if plan.ID == "" || plan.ID != planDigest(identity) {
		return Plan{}, errors.New("governance plan identity is invalid")
	}
	return plan, nil
}

func marshalPlan(plan Plan) ([]byte, error) {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode governance plan: %w", err)
	}
	return append(data, '\n'), nil
}

func writePlan(writer io.Writer, plan Plan) error {
	data, err := marshalPlan(plan)
	if err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("write governance plan: %w", err)
	}
	return nil
}

func writeCLIError(writer io.Writer, err error) {
	_, _ = fmt.Fprintln(writer, "github-ci-govern:", strings.TrimSpace(err.Error()))
}
