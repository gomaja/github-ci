package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

const schemaVersion = 1

var buildTagPattern = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)

// Profile identifies the fixed assurance profile applied to a consumer.
type Profile string

const (
	ProfileGoStrict       Profile = "go-strict"
	ProfileGoLibrary      Profile = "go-library"
	ProfileRepositoryOnly Profile = "repository-only"
)

// Module is a repository-relative Go module path.
type Module string

// Service identifies a supported service fixture.
type Service string

const (
	ServicePostgreSQL Service = "postgresql"
	ServiceRedis      Service = "redis"
)

// Consumer configures a reusable workflow consumer.
type Consumer struct {
	SchemaVersion int       `yaml:"schema-version"`
	Profile       Profile   `yaml:"profile"`
	Modules       []Module  `yaml:"modules,omitempty"`
	BuildTags     []string  `yaml:"build-tags,omitempty"`
	Services      []Service `yaml:"services,omitempty"`
	Generated     []string  `yaml:"generated,omitempty"`
	Exceptions    string    `yaml:"exceptions,omitempty"`
}

// DecodeConsumer parses and validates exactly one strict YAML document.
func DecodeConsumer(reader io.Reader) (Consumer, error) {
	var consumer Consumer
	if err := decodeStrictYAML(reader, &consumer); err != nil {
		return Consumer{}, err
	}
	if err := consumer.Validate(); err != nil {
		return Consumer{}, err
	}
	return consumer, nil
}

// Validate verifies the semantic constraints of a consumer configuration.
func (consumer Consumer) Validate() error {
	if consumer.SchemaVersion != schemaVersion {
		return fmt.Errorf("schema-version must be %d", schemaVersion)
	}
	if !isProfile(consumer.Profile) {
		return fmt.Errorf("unsupported profile %q", consumer.Profile)
	}

	modules := make(map[Module]struct{}, len(consumer.Modules))
	for _, module := range consumer.Modules {
		if err := validateRelativePath("module", string(module)); err != nil {
			return err
		}
		if _, exists := modules[module]; exists {
			return fmt.Errorf("duplicate module %q", module)
		}
		modules[module] = struct{}{}
	}

	for _, buildTag := range consumer.BuildTags {
		if err := validateText("build tag", buildTag); err != nil {
			return err
		}
		if !buildTagPattern.MatchString(buildTag) {
			return fmt.Errorf("invalid build tag %q", buildTag)
		}
	}

	for _, service := range consumer.Services {
		if service != ServicePostgreSQL && service != ServiceRedis {
			return fmt.Errorf("unsupported service %q", service)
		}
	}

	for _, generated := range consumer.Generated {
		if err := validateRelativePath("generated path", generated); err != nil {
			return err
		}
	}
	if consumer.Exceptions != "" {
		if err := validateRelativePath("exceptions path", consumer.Exceptions); err != nil {
			return err
		}
	}

	return nil
}

func decodeStrictYAML(reader io.Reader, destination any) error {
	if reader == nil {
		return errors.New("configuration reader is nil")
	}

	decoder := yaml.NewDecoder(reader)
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty configuration")
		}
		return fmt.Errorf("decode configuration: %w", err)
	}
	if node.Kind == 0 || len(node.Content) == 0 {
		return errors.New("empty configuration")
	}

	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("configuration contains multiple YAML documents")
		}
		return fmt.Errorf("decode trailing configuration document: %w", err)
	}

	encoded, err := yaml.Marshal(&node)
	if err != nil {
		return fmt.Errorf("encode configuration node: %w", err)
	}
	strictDecoder := yaml.NewDecoder(bytes.NewReader(encoded))
	strictDecoder.KnownFields(true)
	if err := strictDecoder.Decode(destination); err != nil {
		return fmt.Errorf("decode configuration: %w", err)
	}
	return nil
}

func isProfile(profile Profile) bool {
	return profile == ProfileGoStrict || profile == ProfileGoLibrary || profile == ProfileRepositoryOnly
}

func validateRelativePath(field, value string) error {
	if err := validateText(field, value); err != nil {
		return err
	}
	if path.IsAbs(value) || strings.HasPrefix(value, "\\") || windowsAbsolutePath(value) {
		return fmt.Errorf("%s must not be absolute: %q", field, value)
	}
	if strings.Contains(value, "\\") {
		return fmt.Errorf("%s must use slash-separated paths: %q", field, value)
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return fmt.Errorf("%s must not contain traversal: %q", field, value)
		}
	}
	return nil
}

func windowsAbsolutePath(value string) bool {
	return len(value) >= 3 && unicode.IsLetter(rune(value[0])) && value[1] == ':' && (value[2] == '/' || value[2] == '\\')
}

func validateText(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}
