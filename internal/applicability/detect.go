package applicability

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/gomaja/github-ci/internal/config"
	"github.com/gomaja/github-ci/internal/evidence"
)

const (
	// DetectorVersion identifies the tracked-tree applicability algorithm.
	DetectorVersion = "applicability/v1"
	maxTrackedFile  = 268_435_456
	maxTrackedTree  = 2_147_483_648
)

// Input binds detection to consumer configuration and immutable policy identity.
type Input struct {
	Consumer     config.Consumer
	SubjectSHA   string
	PolicySHA256 string
	Catalog      Catalog
}

type trackedFile struct {
	path string
	mode fs.FileMode
	data []byte
}

type repositoryShape struct {
	modules    []string
	ordinaryGo bool
	shell      bool
	docker     bool
	workflow   bool
	terraform  bool
	markdown   bool
	yaml       bool
	json       bool
}

// Detect builds a deterministic assurance plan from a tracked-only file system.
func Detect(tracked fs.FS, input Input) (evidence.Plan, error) {
	if tracked == nil {
		return evidence.Plan{}, errors.New("tracked filesystem must not be nil")
	}
	if err := input.Consumer.Validate(); err != nil {
		return evidence.Plan{}, fmt.Errorf("consumer configuration: %w", err)
	}
	if err := input.Catalog.Validate(); err != nil {
		return evidence.Plan{}, fmt.Errorf("catalog: %w", err)
	}
	if err := input.Catalog.validateDefaultPolicy(); err != nil {
		return evidence.Plan{}, err
	}
	files, err := readTrackedFiles(tracked)
	if err != nil {
		return evidence.Plan{}, err
	}
	if input.Consumer.Exceptions != "" && !slices.ContainsFunc(files, func(file trackedFile) bool {
		return file.path == input.Consumer.Exceptions
	}) {
		return evidence.Plan{}, fmt.Errorf("configured exceptions manifest %q is not tracked", input.Consumer.Exceptions)
	}
	shape := inspect(files, input.Consumer.Generated)
	if err := validateModules(input.Consumer, shape.modules); err != nil {
		return evidence.Plan{}, err
	}

	expected := make([]evidence.Expected, 0, len(input.Catalog))
	for _, entry := range input.Catalog {
		if !slices.Contains(entry.Profiles, input.Consumer.Profile) {
			continue
		}
		applicable := capabilityApplies(entry.Capability, shape)
		item := evidence.Expected{
			Tool:          entry.Tool,
			CommandID:     entry.CommandID,
			ParserVersion: entry.ParserVersion,
			Applicability: evidence.Applicable,
		}
		if !applicable {
			item.Applicability = evidence.NotApplicable
			item.ReasonCode = entry.ReasonCode
		}
		expected = append(expected, item)
	}
	slices.SortFunc(expected, func(left, right evidence.Expected) int {
		return strings.Compare(left.Identity(), right.Identity())
	})
	plan := evidence.Plan{
		SchemaVersion:   evidence.SchemaVersion,
		DetectorVersion: DetectorVersion,
		SubjectSHA:      input.SubjectSHA,
		TreeSHA256:      treeDigest(files),
		PolicySHA256:    input.PolicySHA256,
		Expected:        expected,
	}
	if err := evidence.ValidatePlan(plan); err != nil {
		return evidence.Plan{}, fmt.Errorf("validate applicability plan: %w", err)
	}
	return plan, nil
}

func readTrackedFiles(tracked fs.FS) ([]trackedFile, error) {
	return readTrackedFilesWithLimits(tracked, maxTrackedFile, maxTrackedTree)
}

func readTrackedFilesWithLimits(tracked fs.FS, maxFile, maxTree int64) ([]trackedFile, error) {
	var files []trackedFile
	var total int64
	err := fs.WalkDir(tracked, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk tracked path %q: %w", name, walkErr)
		}
		if name == "." || entry.IsDir() {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("tracked path %q is a symlink", name)
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat tracked path %q: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("tracked path %q has unsupported file mode %s", name, info.Mode())
		}
		if info.Size() > maxFile {
			return fmt.Errorf("tracked path %q exceeds %d bytes", name, maxFile)
		}
		file, err := tracked.Open(name)
		if err != nil {
			return fmt.Errorf("open tracked path %q: %w", name, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxFile+1))
		closeErr := file.Close()
		if readErr != nil {
			return fmt.Errorf("read tracked path %q: %w", name, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close tracked path %q: %w", name, closeErr)
		}
		if int64(len(data)) > maxFile {
			return fmt.Errorf("tracked path %q exceeds %d bytes", name, maxFile)
		}
		total += int64(len(data))
		if total > maxTree {
			return fmt.Errorf("tracked tree exceeds %d bytes", maxTree)
		}
		files = append(files, trackedFile{path: name, mode: info.Mode(), data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(left, right trackedFile) int { return strings.Compare(left.path, right.path) })
	return files, nil
}

func inspect(files []trackedFile, generated []string) repositoryShape {
	shape := repositoryShape{}
	for _, file := range files {
		base := path.Base(file.path)
		extension := strings.ToLower(path.Ext(base))
		if base == "go.mod" {
			shape.modules = append(shape.modules, path.Dir(file.path))
		}
		if extension == ".go" && !isGenerated(file.path, generated) {
			shape.ordinaryGo = true
		}
		if IsShellFile(file.path, file.data) {
			shape.shell = true
		}
		if isDockerfile(base) {
			shape.docker = true
		}
		if strings.HasPrefix(file.path, ".github/workflows/") && (extension == ".yml" || extension == ".yaml") {
			shape.workflow = true
		}
		if extension == ".tf" {
			shape.terraform = true
		}
		if extension == ".md" || extension == ".markdown" {
			shape.markdown = true
		}
		if extension == ".yml" || extension == ".yaml" {
			shape.yaml = true
		}
		if extension == ".json" {
			shape.json = true
		}
	}
	slices.Sort(shape.modules)
	return shape
}

func validateModules(consumer config.Consumer, detected []string) error {
	isGoProfile := consumer.Profile == config.ProfileGoStrict || consumer.Profile == config.ProfileGoLibrary
	if isGoProfile && len(detected) == 0 {
		return fmt.Errorf("profile %q requires a tracked go.mod", consumer.Profile)
	}
	if !isGoProfile && len(detected) != 0 {
		return fmt.Errorf("profile %q would omit tracked Go modules", consumer.Profile)
	}
	if len(consumer.Modules) == 0 {
		return nil
	}
	configured := make([]string, len(consumer.Modules))
	for index, module := range consumer.Modules {
		configured[index] = string(module)
	}
	slices.Sort(configured)
	for _, module := range configured {
		if !slices.Contains(detected, module) {
			return fmt.Errorf("configured module %q has no tracked go.mod", module)
		}
	}
	for _, module := range detected {
		if !slices.Contains(configured, module) {
			return fmt.Errorf("configuration omits tracked module %q", module)
		}
	}
	return nil
}

func capabilityApplies(capability Capability, shape repositoryShape) bool {
	switch capability {
	case CapabilityAlways:
		return true
	case CapabilityGo:
		return len(shape.modules) != 0
	case CapabilityOrdinaryGo:
		return shape.ordinaryGo
	case CapabilityShell:
		return shape.shell
	case CapabilityDocker:
		return shape.docker
	case CapabilityWorkflow:
		return shape.workflow
	case CapabilityTerraform:
		return shape.terraform
	case CapabilityMarkdown:
		return shape.markdown
	case CapabilityYAML:
		return shape.yaml
	case CapabilityJSON:
		return shape.json
	default:
		return false
	}
}

func isGenerated(name string, generated []string) bool {
	for _, prefix := range generated {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	return false
}

// IsShellFile reports whether a tracked path is a supported shell source file.
func IsShellFile(name string, data []byte) bool {
	switch strings.ToLower(path.Ext(path.Base(name))) {
	case ".sh", ".bash", ".bats", ".zsh", ".ksh":
		return true
	}
	line, _, _ := bytes.Cut(data, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if !bytes.HasPrefix(line, []byte("#!")) {
		return false
	}
	raw := string(line[2:])
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return false
	}
	if !path.IsAbs(fields[0]) {
		return false
	}
	if isSupportedShellInterpreter(fields[0]) {
		return true
	}
	if path.Base(fields[0]) != "env" {
		return false
	}
	arguments := fields[1:]
	_, usesSplitString := expandEnvSplitString(arguments)
	if !usesSplitString {
		return envSelectsSupportedShell(arguments)
	}
	arguments, valid := splitEnvString(raw)
	if !valid {
		return false
	}
	arguments, usesSplitString = expandEnvSplitString(envCommandArguments(arguments))
	return usesSplitString && envSelectsSupportedShell(arguments)
}

func envCommandArguments(arguments []string) []string {
	if len(arguments) == 0 {
		return nil
	}
	return arguments[1:]
}

func expandEnvSplitString(arguments []string) ([]string, bool) {
	for len(arguments) != 0 {
		argument := arguments[0]
		if isDetachedEnvSplitOption(argument) {
			return arguments[1:], true
		}
		switch {
		case strings.HasPrefix(argument, "--split-string="):
			value := strings.TrimPrefix(argument, "--split-string=")
			if value == "" {
				return nil, true
			}
			return append([]string{value}, arguments[1:]...), true
		case strings.HasPrefix(argument, "-S"):
			return append([]string{argument[2:]}, arguments[1:]...), true
		case isEnvEndOptions(argument):
			return arguments, false
		case isEnvOptionWithDetachedValue(argument):
			if len(arguments) == 1 {
				return arguments, false
			}
			arguments = arguments[2:]
		case isEnvOptionWithAttachedValue(argument), isEnvOptionWithoutValue(argument):
			arguments = arguments[1:]
		case strings.ContainsRune(argument, '='):
			return arguments, false
		case strings.HasPrefix(argument, "-"):
			flags, value, found := strings.Cut(argument[1:], "S")
			if !found || !isEnvFlagBundle(flags) {
				return arguments, false
			}
			if value == "" {
				return arguments[1:], true
			}
			return append([]string{value}, arguments[1:]...), true
		default:
			return arguments, false
		}
	}
	return arguments, false
}

func isDetachedEnvSplitOption(argument string) bool {
	return argument == "-S" || argument == "--split-string"
}

func isEnvEndOptions(argument string) bool {
	return argument == "--"
}

func isEnvFlagBundle(flags string) bool {
	for _, flag := range flags {
		if flag != '0' && flag != 'i' && flag != 'v' {
			return false
		}
	}
	return true
}

func isEnvOptionWithDetachedValue(argument string) bool {
	switch argument {
	case "-u", "--unset", "-C", "--chdir":
		return true
	default:
		return false
	}
}

func isEnvOptionWithAttachedValue(argument string) bool {
	return ((strings.HasPrefix(argument, "-u") || strings.HasPrefix(argument, "-C")) && len(argument) > 2) ||
		strings.HasPrefix(argument, "--unset=") || strings.HasPrefix(argument, "--chdir=")
}

func isEnvOptionWithoutValue(argument string) bool {
	switch argument {
	case "-", "-i", "-0", "-v", "--ignore-environment", "--null", "--debug",
		"--block-signal", "--default-signal", "--ignore-signal", "--list-signal-handling":
		return true
	default:
		return strings.HasPrefix(argument, "--block-signal=") ||
			strings.HasPrefix(argument, "--default-signal=") ||
			strings.HasPrefix(argument, "--ignore-signal=") ||
			(strings.HasPrefix(argument, "-") && isEnvFlagBundle(argument[1:]))
	}
}

// splitEnvString lexes the GNU Coreutils env -S quoting and escape rules.
func splitEnvString(input string) ([]string, bool) {
	state := envStringState{}
	remaining := []byte(input)
	for len(remaining) != 0 {
		character := remaining[0]
		remaining = remaining[1:]
		if state.quote == 0 && isEnvSpace(character) {
			state.flush()
			continue
		}
		if state.consumeQuote(character) {
			continue
		}
		if state.quote == 0 && character == '#' && !state.inArgument {
			break
		}
		if character != '\\' {
			state.write(character)
			continue
		}
		if len(remaining) == 0 {
			return nil, false
		}
		next := remaining[0]
		remaining = remaining[1:]
		stop, valid := state.consumeEscape(next)
		if !valid {
			return nil, false
		}
		if stop {
			state.flush()
			return state.arguments, true
		}
	}
	if state.quote != 0 {
		return nil, false
	}
	state.flush()
	return state.arguments, true
}

type envStringState struct {
	arguments  []string
	current    strings.Builder
	quote      byte
	inArgument bool
}

func (state *envStringState) flush() {
	if !state.inArgument {
		return
	}
	state.arguments = append(state.arguments, state.current.String())
	state.current.Reset()
	state.inArgument = false
}

func (state *envStringState) write(character byte) {
	state.current.WriteByte(character)
	state.inArgument = true
}

func (state *envStringState) consumeQuote(character byte) bool {
	if character != '\'' && character != '"' {
		return false
	}
	if state.quote == 0 {
		state.quote = character
		state.inArgument = true
		return true
	}
	if state.quote == character {
		state.quote = 0
		return true
	}
	return false
}

func (state *envStringState) consumeEscape(character byte) (bool, bool) {
	if state.quote == '\'' && character != '\'' && character != '\\' {
		state.write('\\')
		state.write(character)
		return false, true
	}
	switch character {
	case 'c':
		return true, state.quote == 0
	case '_':
		if state.quote == 0 {
			state.flush()
		} else {
			state.write(' ')
		}
	case 'f':
		state.write('\f')
	case 'n':
		state.write('\n')
	case 'r':
		state.write('\r')
	case 't':
		state.write('\t')
	case 'v':
		state.write('\v')
	case '#', '$', '"', '\'', '\\':
		state.write(character)
	default:
		return false, false
	}
	return false, true
}

func isEnvSpace(character byte) bool {
	switch character {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

func envSelectsSupportedShell(arguments []string) bool {
	for len(arguments) != 0 {
		argument := arguments[0]
		switch {
		case isEnvEndOptions(argument):
			return envCommandSelectsSupportedShell(arguments[1:])
		case isEnvOptionWithDetachedValue(argument):
			if len(arguments) == 1 {
				return false
			}
			arguments = arguments[2:]
		case isEnvOptionWithAttachedValue(argument), isEnvOptionWithoutValue(argument):
			arguments = arguments[1:]
		case strings.HasPrefix(argument, "-"):
			return false
		default:
			return envCommandSelectsSupportedShell(arguments)
		}
	}
	return false
}

func envCommandSelectsSupportedShell(arguments []string) bool {
	for len(arguments) != 0 && strings.ContainsRune(arguments[0], '=') {
		arguments = arguments[1:]
	}
	return len(arguments) != 0 && isSupportedShellInterpreter(arguments[0])
}

func isSupportedShellInterpreter(interpreter string) bool {
	switch path.Base(interpreter) {
	case "sh", "bash", "zsh", "ksh":
		return true
	default:
		return false
	}
}

func isDockerfile(base string) bool {
	lower := strings.ToLower(base)
	return lower == "dockerfile" || lower == "containerfile" ||
		strings.HasPrefix(lower, "dockerfile.") || strings.HasPrefix(lower, "containerfile.") ||
		strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile")
}

func treeDigest(files []trackedFile) string {
	hash := sha256.New()
	var integer [8]byte
	for _, file := range files {
		binary.BigEndian.PutUint64(integer[:], uint64(len(file.path)))
		_, _ = hash.Write(integer[:])
		_, _ = hash.Write([]byte(file.path))
		binary.BigEndian.PutUint64(integer[:], uint64(file.mode))
		_, _ = hash.Write(integer[:])
		binary.BigEndian.PutUint64(integer[:], uint64(len(file.data)))
		_, _ = hash.Write(integer[:])
		_, _ = hash.Write(file.data)
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}
