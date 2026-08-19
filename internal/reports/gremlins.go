package reports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode"

	"github.com/gomaja/github-ci/internal/pathpolicy"
)

const (
	maxGremlinsJSONDepth  = 32
	gremlinsNoResultsLine = "No results to report."
)

var gremlinsPropertyNames = [...]string{
	"go_module",
	"files",
	"test_efficacy",
	"mutations_coverage",
	"mutants_total",
	"mutants_killed",
	"mutants_lived",
	"mutants_not_viable",
	"mutants_not_covered",
	"elapsed_time",
	"mutator_statistics",
	"file_name",
	"mutations",
	"type",
	"status",
	"line",
	"column",
	"arithmetic_base",
	"conditionals_negation",
	"conditionals_boundary",
	"increment_decrement",
	"invert_assignments",
	"invert_bitwise",
	"invert_bitwise_assignments",
	"invert_logical",
	"invert_loop_ctrl",
	"invert_negatives",
	"remove_self_assignments",
}

type gremlinsReport struct {
	GoModule          *string             `json:"go_module"`
	Files             *[]gremlinsFile     `json:"files"`
	TestEfficacy      *float64            `json:"test_efficacy"`
	MutationsCoverage *float64            `json:"mutations_coverage"`
	MutantsTotal      *int                `json:"mutants_total"`
	MutantsKilled     *int                `json:"mutants_killed"`
	MutantsLived      *int                `json:"mutants_lived"`
	MutantsNotViable  *int                `json:"mutants_not_viable"`
	MutantsNotCovered *int                `json:"mutants_not_covered"`
	ElapsedTime       *float64            `json:"elapsed_time"`
	MutatorStatistics *gremlinsStatistics `json:"mutator_statistics"`
}

// GremlinsNoResultsEvidence records a pinned Gremlins run with no mutation points.
type GremlinsNoResultsEvidence struct {
	SchemaVersion int    `json:"schema_version"`
	Tool          string `json:"tool"`
	ToolVersion   string `json:"tool_version"`
	GoModule      string `json:"go_module"`
	Outcome       string `json:"outcome"`
}

type gremlinsFile struct {
	Filename  *string             `json:"file_name"`
	Mutations *[]gremlinsMutation `json:"mutations"`
}

type gremlinsMutation struct {
	Type   *string `json:"type"`
	Status *string `json:"status"`
	Line   *int    `json:"line"`
	Column *int    `json:"column"`
}

type gremlinsStatistics struct {
	ArithmeticBase           gremlinsOptionalCount `json:"arithmetic_base,omitempty"`
	ConditionalsNegation     gremlinsOptionalCount `json:"conditionals_negation,omitempty"`
	ConditionalsBoundary     gremlinsOptionalCount `json:"conditionals_boundary,omitempty"`
	IncrementDecrement       gremlinsOptionalCount `json:"increment_decrement,omitempty"`
	InvertAssignments        gremlinsOptionalCount `json:"invert_assignments,omitempty"`
	InvertBitwise            gremlinsOptionalCount `json:"invert_bitwise,omitempty"`
	InvertBitwiseAssignments gremlinsOptionalCount `json:"invert_bitwise_assignments,omitempty"`
	InvertLogical            gremlinsOptionalCount `json:"invert_logical,omitempty"`
	InvertLoopCtrl           gremlinsOptionalCount `json:"invert_loop_ctrl,omitempty"`
	InvertNegatives          gremlinsOptionalCount `json:"invert_negatives,omitempty"`
	RemoveSelfAssignments    gremlinsOptionalCount `json:"remove_self_assignments,omitempty"`
}

type gremlinsOptionalCount int

func (count *gremlinsOptionalCount) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("mutator statistic must be an integer")
	}
	var value int
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("mutator statistic must be an integer: %w", err)
	}
	*count = gremlinsOptionalCount(value)
	return nil
}

// ValidateGremlins validates complete mutation evidence emitted by pinned Gremlins v0.6.0.
func ValidateGremlins(reader io.Reader, expectedModule string) error {
	if err := validateGremlinsModule(expectedModule); err != nil {
		return err
	}
	data, err := readBounded(reader)
	if err != nil {
		return err
	}
	if err := validateGremlinsUniqueKeys(data); err != nil {
		return err
	}
	var report gremlinsReport
	if err := decodeStrictJSON(data, &report); err != nil {
		return fmt.Errorf("decode Gremlins report: %w", err)
	}
	return validateGremlinsReport(report, expectedModule)
}

// ValidateGremlinsNoResults validates the terminal message emitted by pinned
// Gremlins v0.6.0 when its result set contains no mutants.
func ValidateGremlinsNoResults(reader io.Reader, expectedModule string) (GremlinsNoResultsEvidence, error) {
	if err := validateGremlinsModule(expectedModule); err != nil {
		return GremlinsNoResultsEvidence{}, err
	}
	data, err := readBounded(reader)
	if err != nil {
		return GremlinsNoResultsEvidence{}, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	markerCount := 0
	finalLine := ""
	for _, line := range lines {
		if line == gremlinsNoResultsLine {
			markerCount++
		}
		if strings.TrimSpace(line) != "" {
			finalLine = line
		}
	}
	if markerCount != 1 {
		return GremlinsNoResultsEvidence{}, errors.New("gremlins no-results marker must appear exactly once")
	}
	if finalLine != gremlinsNoResultsLine {
		return GremlinsNoResultsEvidence{}, errors.New("gremlins no-results marker must be the final non-empty line")
	}
	return GremlinsNoResultsEvidence{
		SchemaVersion: 1,
		Tool:          "gremlins",
		ToolVersion:   "0.6.0",
		GoModule:      expectedModule,
		Outcome:       "no-mutants",
	}, nil
}

func validateGremlinsModule(expectedModule string) error {
	if strings.TrimSpace(expectedModule) == "" {
		return errors.New("expected module must not be empty")
	}
	if strings.ContainsFunc(expectedModule, unicode.IsControl) {
		return errors.New("expected module contains a control character")
	}
	return nil
}

func validateGremlinsReport(report gremlinsReport, expectedModule string) error {
	if report.GoModule == nil {
		return errors.New("go_module is required")
	}
	if *report.GoModule != expectedModule {
		return fmt.Errorf("go_module %q does not match expected module %q", *report.GoModule, expectedModule)
	}
	if report.Files == nil {
		return errors.New("files is required")
	}
	if len(*report.Files) == 0 {
		return errors.New("files must contain at least one file")
	}
	if err := validateGremlinsScalars(report); err != nil {
		return err
	}
	statusCounts, typeCounts, err := validateGremlinsFiles(*report.Files)
	if err != nil {
		return err
	}
	if err := validateGremlinsSummary(report, statusCounts); err != nil {
		return err
	}
	return validateGremlinsStatistics(*report.MutatorStatistics, typeCounts)
}

func validateGremlinsScalars(report gremlinsReport) error {
	percentages := []struct {
		name  string
		value *float64
	}{
		{name: "test_efficacy", value: report.TestEfficacy},
		{name: "mutations_coverage", value: report.MutationsCoverage},
	}
	for _, percentage := range percentages {
		if percentage.value == nil {
			return fmt.Errorf("%s is required", percentage.name)
		}
		if *percentage.value != 100 {
			return fmt.Errorf("%s must equal 100", percentage.name)
		}
	}
	counts := gremlinsSummaryCounts(report)
	for name, count := range counts {
		if count == nil {
			return fmt.Errorf("%s is required", name)
		}
		if *count < 0 {
			return fmt.Errorf("%s must not be negative", name)
		}
	}
	if report.ElapsedTime == nil {
		return errors.New("elapsed_time is required")
	}
	if math.IsNaN(*report.ElapsedTime) {
		return errors.New("elapsed_time must not be negative or non-finite")
	}
	if math.IsInf(*report.ElapsedTime, 0) {
		return errors.New("elapsed_time must not be negative or non-finite")
	}
	if *report.ElapsedTime < 0 {
		return errors.New("elapsed_time must not be negative or non-finite")
	}
	if report.MutatorStatistics == nil {
		return errors.New("mutator_statistics is required")
	}
	return nil
}

func gremlinsSummaryCounts(report gremlinsReport) map[string]*int {
	return map[string]*int{
		"mutants_total":       report.MutantsTotal,
		"mutants_killed":      report.MutantsKilled,
		"mutants_lived":       report.MutantsLived,
		"mutants_not_viable":  report.MutantsNotViable,
		"mutants_not_covered": report.MutantsNotCovered,
	}
}

func validateGremlinsFiles(files []gremlinsFile) (map[string]int, map[string]int, error) {
	statusCounts := make(map[string]int)
	typeCounts := make(map[string]int)
	seenFiles := make(map[string]struct{}, len(files))
	for fileIndex, file := range files {
		if file.Filename == nil {
			return nil, nil, fmt.Errorf("file %d file_name is required", fileIndex)
		}
		if err := pathpolicy.Validate("gremlins file_name", *file.Filename); err != nil {
			return nil, nil, fmt.Errorf("file %d: %w", fileIndex, err)
		}
		if _, exists := seenFiles[*file.Filename]; exists {
			return nil, nil, fmt.Errorf("duplicate file_name %q", *file.Filename)
		}
		seenFiles[*file.Filename] = struct{}{}
		if file.Mutations == nil {
			return nil, nil, fmt.Errorf("file %q mutations is required", *file.Filename)
		}
		if len(*file.Mutations) == 0 {
			return nil, nil, fmt.Errorf("file %q mutations must not be empty", *file.Filename)
		}
		if err := validateGremlinsMutations(*file.Filename, *file.Mutations, statusCounts, typeCounts); err != nil {
			return nil, nil, err
		}
	}
	return statusCounts, typeCounts, nil
}

func validateGremlinsMutations(filename string, mutations []gremlinsMutation, statusCounts, typeCounts map[string]int) error {
	type mutationIdentity struct {
		typeName string
		line     int
		column   int
	}
	seen := make(map[mutationIdentity]struct{}, len(mutations))
	supportedTypes := gremlinsStatisticNames()
	for index, mutation := range mutations {
		if mutation.Type == nil {
			return fmt.Errorf("file %q mutation %d type is required", filename, index)
		}
		if _, supported := supportedTypes[*mutation.Type]; !supported {
			return fmt.Errorf("file %q mutation %d has unsupported mutation type %q", filename, index, *mutation.Type)
		}
		if mutation.Status == nil {
			return fmt.Errorf("file %q mutation %d status is required", filename, index)
		}
		if *mutation.Status != "KILLED" && *mutation.Status != "NOT VIABLE" {
			return fmt.Errorf("file %q mutation %d has blocking mutation status %q", filename, index, *mutation.Status)
		}
		if mutation.Line == nil || mutation.Column == nil {
			return fmt.Errorf("file %q mutation %d line and column are required", filename, index)
		}
		if *mutation.Line <= 0 || *mutation.Column <= 0 {
			return fmt.Errorf("file %q mutation %d must have positive line and column", filename, index)
		}
		identity := mutationIdentity{typeName: *mutation.Type, line: *mutation.Line, column: *mutation.Column}
		if _, exists := seen[identity]; exists {
			return fmt.Errorf("file %q has duplicate mutation %s at %d:%d", filename, identity.typeName, identity.line, identity.column)
		}
		seen[identity] = struct{}{}
		statusCounts[*mutation.Status]++
		typeCounts[*mutation.Type]++
	}
	return nil
}

func validateGremlinsSummary(report gremlinsReport, statuses map[string]int) error {
	if *report.MutantsKilled != statuses["KILLED"] {
		return errors.New("mutants_killed does not match mutation statuses")
	}
	if *report.MutantsLived != 0 {
		return errors.New("mutants_lived must be zero")
	}
	if *report.MutantsNotViable != statuses["NOT VIABLE"] {
		return errors.New("mutants_not_viable does not match mutation statuses")
	}
	if *report.MutantsNotCovered != 0 {
		return errors.New("mutants_not_covered must be zero")
	}
	if *report.MutantsKilled == 0 {
		return errors.New("mutants_killed must be positive")
	}
	wantTotal := *report.MutantsKilled + *report.MutantsNotViable
	if *report.MutantsTotal != wantTotal {
		return errors.New("mutants_total does not match summary counts")
	}
	return nil
}

func validateGremlinsStatistics(statistics gremlinsStatistics, observed map[string]int) error {
	for mutationType, count := range statistics.values() {
		if count < 0 {
			return fmt.Errorf("mutator statistic %s must not be negative", mutationType)
		}
		if count != observed[mutationType] {
			return fmt.Errorf("mutator statistic %s does not match mutation records", mutationType)
		}
	}
	return nil
}

func (statistics gremlinsStatistics) values() map[string]int {
	return map[string]int{
		"ARITHMETIC_BASE":         int(statistics.ArithmeticBase),
		"CONDITIONALS_NEGATION":   int(statistics.ConditionalsNegation),
		"CONDITIONALS_BOUNDARY":   int(statistics.ConditionalsBoundary),
		"INCREMENT_DECREMENT":     int(statistics.IncrementDecrement),
		"INVERT_ASSIGNMENTS":      int(statistics.InvertAssignments),
		"INVERT_BITWISE":          int(statistics.InvertBitwise),
		"INVERT_BWASSIGN":         int(statistics.InvertBitwiseAssignments),
		"INVERT_LOGICAL":          int(statistics.InvertLogical),
		"INVERT_LOOPCTRL":         int(statistics.InvertLoopCtrl),
		"INVERT_NEGATIVES":        int(statistics.InvertNegatives),
		"REMOVE_SELF_ASSIGNMENTS": int(statistics.RemoveSelfAssignments),
	}
}

func gremlinsStatisticNames() map[string]struct{} {
	names := make(map[string]struct{})
	for name := range (gremlinsStatistics{}).values() {
		names[name] = struct{}{}
	}
	return names
}

func validateGremlinsUniqueKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkGremlinsJSONValue(decoder, 0); err != nil {
		return fmt.Errorf("validate Gremlins JSON: %w", err)
	}
	_, err := decoder.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("validate Gremlins JSON trailing value: %w", err)
	}
	return errors.New("validate Gremlins JSON: trailing value")
}

func walkGremlinsJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxGremlinsJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxGremlinsJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			folded := strings.ToLower(key)
			if _, exists := seen[folded]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[folded] = struct{}{}
			if err := validateGremlinsPropertyName(key); err != nil {
				return err
			}
			if err := walkGremlinsJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		return requireGremlinsDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := walkGremlinsJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		return requireGremlinsDelimiter(decoder, ']')
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func validateGremlinsPropertyName(key string) error {
	for _, canonical := range gremlinsPropertyNames {
		if !strings.EqualFold(key, canonical) {
			continue
		}
		if key != canonical {
			return fmt.Errorf("JSON key %q does not match canonical property name %q", key, canonical)
		}
		return nil
	}
	return nil
}

func requireGremlinsDelimiter(decoder *json.Decoder, want json.Delim) error {
	delimiter, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter != want {
		return fmt.Errorf("expected JSON delimiter %q", want)
	}
	return nil
}
