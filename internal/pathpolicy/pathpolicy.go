// Package pathpolicy validates repository-relative paths shared by runtime and schemas.
package pathpolicy

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// SchemaPattern is the JSON Schema-compatible repository-relative path contract.
const SchemaPattern = `^(?:\.|[A-Za-z0-9_][A-Za-z0-9_.-]*|\.[A-Za-z0-9_-][A-Za-z0-9_.-]*)(?:/(?:\.|[A-Za-z0-9_][A-Za-z0-9_.-]*|\.[A-Za-z0-9_-][A-Za-z0-9_.-]*))*$`

var schemaPattern = regexp.MustCompile(SchemaPattern)

// Validate rejects empty, absolute, traversing, non-portable, and schema-incompatible paths.
func Validate(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	if path.IsAbs(value) || strings.HasPrefix(value, `\`) || windowsAbsolutePath(value) {
		return fmt.Errorf("%s must be relative, not absolute: %q", field, value)
	}
	if strings.Contains(value, `\`) {
		return fmt.Errorf("%s must use slash-separated paths: %q", field, value)
	}
	if slices.Contains(strings.Split(value, "/"), "..") {
		return fmt.Errorf("%s must not contain traversal: %q", field, value)
	}
	if !schemaPattern.MatchString(value) {
		return fmt.Errorf("%s is not a valid repository-relative path: %q", field, value)
	}
	return nil
}

func windowsAbsolutePath(value string) bool {
	return len(value) >= 3 && unicode.IsLetter(rune(value[0])) && value[1] == ':' && (value[2] == '/' || value[2] == '\\')
}
