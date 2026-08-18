package evidence

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"testing"
	"unicode/utf8"
)

func TestEvidenceSchemaMatchesValidateRecord(t *testing.T) {
	schema := loadEvidenceSchema(t)
	tests := []struct {
		name   string
		mutate func(*Record)
	}{
		{name: "valid pass"},
		{name: "valid finding", mutate: func(record *Record) { *record = findingRecord() }},
		{name: "valid failed execution", mutate: func(record *Record) { record.Outcome = OutcomeFail; record.ExitCode = 1 }},
		{name: "valid not applicable", mutate: func(record *Record) { *record = notApplicableRecord() }},
		{name: "invalid schema", mutate: func(record *Record) { record.SchemaVersion = "2" }},
		{name: "invalid tool", mutate: func(record *Record) { record.Tool = "Staticcheck" }},
		{name: "empty tool version", mutate: func(record *Record) { record.ToolVersion = "" }},
		{name: "control tool version", mutate: func(record *Record) { record.ToolVersion = "bad\u0007version" }},
		{name: "invalid policy digest", mutate: func(record *Record) { record.PolicyVersion = "sha256:bad" }},
		{name: "invalid subject sha", mutate: func(record *Record) { record.SubjectSHA = "main" }},
		{name: "invalid applicability", mutate: func(record *Record) { record.Applicability = "sometimes" }},
		{name: "absolute command id", mutate: func(record *Record) { record.CommandID = "/tmp/report" }},
		{name: "spaced command id", mutate: func(record *Record) { record.CommandID = "bad path" }},
		{name: "negative exit code", mutate: func(record *Record) { record.ExitCode = -1 }},
		{name: "negative findings", mutate: func(record *Record) { record.FindingCount = -1 }},
		{name: "negative suppressions", mutate: func(record *Record) { record.Suppressed = -1 }},
		{name: "unknown outcome", mutate: func(record *Record) { record.Outcome = "warning" }},
		{name: "applicable n/a", mutate: func(record *Record) { record.Outcome = OutcomeNotApplicable }},
		{name: "applicable missing report", mutate: func(record *Record) { record.ReportSHA256 = "" }},
		{name: "pass nonzero exit", mutate: func(record *Record) { record.ExitCode = 1 }},
		{name: "pass with finding", mutate: func(record *Record) { record.FindingCount = 1 }},
		{name: "n/a with report", mutate: func(record *Record) { *record = notApplicableRecord(); record.ReportSHA256 = testReportSHA }},
		{name: "n/a with finding", mutate: func(record *Record) { *record = notApplicableRecord(); record.FindingCount = 1 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validRecord()
			if test.mutate != nil {
				test.mutate(&record)
			}
			runtimeErr := ValidateRecord(record)
			schemaErr := validateRecordAgainstSchema(record, schema)
			if (runtimeErr == nil) != (schemaErr == nil) {
				t.Fatalf("runtime error = %v; schema error = %v", runtimeErr, schemaErr)
			}
		})
	}
}

func TestEvidenceSchemaRejectsPassingNonzeroResults(t *testing.T) {
	schema := loadEvidenceSchema(t)
	commandID := schema.Properties["command_id"]
	commandID.Pattern = ""
	schema.Properties["command_id"] = commandID

	for _, mutate := range []func(*Record){
		func(record *Record) { record.ExitCode = 1 },
		func(record *Record) { record.FindingCount = 1 },
	} {
		record := validRecord()
		mutate(&record)
		if err := validateRecordAgainstSchema(record, schema); err == nil {
			t.Fatal("evidence schema accepted a passing record with a nonzero result")
		}
	}
}

type schemaRule struct {
	Type                 string                `json:"type"`
	AdditionalProperties *bool                 `json:"additionalProperties"`
	Required             []string              `json:"required"`
	Properties           map[string]schemaRule `json:"properties"`
	AllOf                []schemaRule          `json:"allOf"`
	If                   *schemaRule           `json:"if"`
	Then                 *schemaRule           `json:"then"`
	Not                  *schemaRule           `json:"not"`
	Const                any                   `json:"const"`
	Enum                 []any                 `json:"enum"`
	Minimum              *float64              `json:"minimum"`
	MinLength            *int                  `json:"minLength"`
	Pattern              string                `json:"pattern"`
}

func loadEvidenceSchema(t *testing.T) schemaRule {
	t.Helper()
	data, err := os.ReadFile("../../schemas/evidence.schema.json")
	if err != nil {
		t.Fatalf("read evidence schema: %v", err)
	}
	var schema schemaRule
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("decode evidence schema: %v", err)
	}
	return schema
}

func validateRecordAgainstSchema(record Record, schema schemaRule) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode record: %w", err)
	}
	return validateSchemaRule(schema, value, "record")
}

func validateSchemaRule(rule schemaRule, value any, field string) error {
	if err := validateSchemaIdentity(rule, value, field); err != nil {
		return err
	}
	if err := validateSchemaType(rule, value, field); err != nil {
		return err
	}
	if err := validateSchemaScalar(rule, value, field); err != nil {
		return err
	}
	if err := validateSchemaObject(rule, value, field); err != nil {
		return err
	}
	return validateSchemaCombinators(rule, value, field)
}

func validateSchemaIdentity(rule schemaRule, value any, field string) error {
	if rule.Const != nil && !reflect.DeepEqual(rule.Const, value) {
		return fmt.Errorf("%s does not equal const", field)
	}
	if len(rule.Enum) != 0 {
		matched := false
		for _, candidate := range rule.Enum {
			matched = matched || reflect.DeepEqual(candidate, value)
		}
		if !matched {
			return fmt.Errorf("%s is not in enum", field)
		}
	}
	return nil
}

func validateSchemaType(rule schemaRule, value any, field string) error {
	switch rule.Type {
	case "object":
		if _, ok := value.(map[string]any); !ok {
			return fmt.Errorf("%s is not an object", field)
		}
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s is not a string", field)
		}
	case "integer":
		number, ok := value.(float64)
		if !ok || math.Trunc(number) != number {
			return fmt.Errorf("%s is not an integer", field)
		}
	}
	return nil
}

func validateSchemaScalar(rule schemaRule, value any, field string) error {
	if text, ok := value.(string); ok {
		if rule.MinLength != nil && utf8.RuneCountInString(text) < *rule.MinLength {
			return fmt.Errorf("%s is shorter than minLength", field)
		}
		if rule.Pattern != "" {
			pattern, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return fmt.Errorf("compile %s pattern: %w", field, err)
			}
			if !pattern.MatchString(text) {
				return fmt.Errorf("%s does not match pattern", field)
			}
		}
	}
	if number, ok := value.(float64); ok && rule.Minimum != nil && number < *rule.Minimum {
		return fmt.Errorf("%s is below minimum", field)
	}
	return nil
}

func validateSchemaObject(rule schemaRule, value any, field string) error {
	if len(rule.Required) != 0 || len(rule.Properties) != 0 {
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not an object", field)
		}
		for _, required := range rule.Required {
			if _, exists := object[required]; !exists {
				return fmt.Errorf("%s.%s is required", field, required)
			}
		}
		if rule.AdditionalProperties != nil && !*rule.AdditionalProperties {
			for name := range object {
				if _, exists := rule.Properties[name]; !exists {
					return fmt.Errorf("%s.%s is not allowed", field, name)
				}
			}
		}
		for name, propertyRule := range rule.Properties {
			property, exists := object[name]
			if exists {
				if err := validateSchemaRule(propertyRule, property, field+"."+name); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateSchemaCombinators(rule schemaRule, value any, field string) error {
	for _, nested := range rule.AllOf {
		if err := validateSchemaRule(nested, value, field); err != nil {
			return err
		}
	}
	if rule.If != nil && validateSchemaRule(*rule.If, value, field) == nil && rule.Then != nil {
		if err := validateSchemaRule(*rule.Then, value, field); err != nil {
			return err
		}
	}
	if rule.Not != nil && validateSchemaRule(*rule.Not, value, field) == nil {
		return fmt.Errorf("%s matches forbidden schema", field)
	}
	return nil
}
