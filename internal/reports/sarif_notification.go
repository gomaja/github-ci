package reports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// OASIS SARIF 2.1.0 + Errata 01 §3.5.3 and the normative schema define GUID syntax.
var sarifGUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

const (
	sarifLevelError   = "error"
	sarifLevelWarning = "warning"
)

type sarifDescriptorKind int

const (
	sarifNotificationDescriptors sarifDescriptorKind = iota
	sarifRuleDescriptors
)

type sarifNotificationResolver struct {
	driver           sarifNotificationComponent
	extensions       []sarifNotificationComponent
	componentsByGUID map[string][]int
}

type sarifNotificationComponent struct {
	name          string
	guid          string
	notifications sarifDescriptorSet
	rules         sarifDescriptorSet
}

type sarifDescriptorSet struct {
	descriptors       []sarifReportingDescriptor
	descriptorsByID   map[string][]int
	descriptorsByGUID map[string][]int
}

type sarifReportingDescriptor struct {
	id           string
	guid         string
	defaultLevel string
}

type sarifDescriptorKey struct {
	component  int
	descriptor int
}

type sarifDescriptorResolution struct {
	key        sarifDescriptorKey
	descriptor *sarifReportingDescriptor
}

func newSARIFNotificationResolver(rawTool json.RawMessage) (*sarifNotificationResolver, error) {
	tool, err := decodeJSONObject(rawTool, "SARIF tool")
	if err != nil {
		return nil, err
	}
	driverRaw, exists := tool["driver"]
	if !exists {
		return nil, errors.New("SARIF tool has no driver")
	}
	driver, err := parseSARIFNotificationComponent(driverRaw, "driver")
	if err != nil {
		return nil, err
	}

	resolver := &sarifNotificationResolver{
		driver:           driver,
		componentsByGUID: make(map[string][]int),
	}
	if driver.guid != "" {
		resolver.componentsByGUID[driver.guid] = append(resolver.componentsByGUID[driver.guid], -1)
	}

	if extensionsRaw, exists := tool["extensions"]; exists {
		var extensions []json.RawMessage
		if err := json.Unmarshal(extensionsRaw, &extensions); err != nil {
			return nil, fmt.Errorf("decode extensions: %w", err)
		}
		if extensions == nil {
			return nil, errors.New("extensions must be an array")
		}
		resolver.extensions = make([]sarifNotificationComponent, len(extensions))
		for index, rawExtension := range extensions {
			extension, err := parseSARIFNotificationComponent(rawExtension, fmt.Sprintf("extension %d", index))
			if err != nil {
				return nil, err
			}
			resolver.extensions[index] = extension
			if extension.guid != "" {
				resolver.componentsByGUID[extension.guid] = append(resolver.componentsByGUID[extension.guid], index)
			}
		}
	}
	return resolver, nil
}

func parseSARIFNotificationComponent(raw json.RawMessage, label string) (sarifNotificationComponent, error) {
	object, err := decodeJSONObject(raw, "SARIF "+label)
	if err != nil {
		return sarifNotificationComponent{}, err
	}
	name, exists, err := sarifStringProperty(object, "name")
	if err != nil || !exists || name == "" {
		return sarifNotificationComponent{}, fmt.Errorf("SARIF %s name must be a nonempty string", label)
	}
	guid, _, err := sarifGUIDProperty(object)
	if err != nil {
		return sarifNotificationComponent{}, fmt.Errorf("SARIF %s: %w", label, err)
	}
	notifications, err := parseSARIFDescriptorSet(object, "notifications", "SARIF "+label+" notification descriptor", true)
	if err != nil {
		return sarifNotificationComponent{}, err
	}
	rules, err := parseSARIFDescriptorSet(object, "rules", "SARIF "+label+" rule descriptor", false)
	if err != nil {
		return sarifNotificationComponent{}, err
	}
	return sarifNotificationComponent{
		name:          name,
		guid:          guid,
		notifications: notifications,
		rules:         rules,
	}, nil
}

func parseSARIFDescriptorSet(object map[string]json.RawMessage, property, label string, parseConfiguration bool) (sarifDescriptorSet, error) {
	set := sarifDescriptorSet{
		descriptorsByID:   make(map[string][]int),
		descriptorsByGUID: make(map[string][]int),
	}
	raw, exists := object[property]
	if !exists {
		return set, nil
	}
	var descriptors []json.RawMessage
	if err := json.Unmarshal(raw, &descriptors); err != nil {
		return sarifDescriptorSet{}, fmt.Errorf("decode %s: %w", property, err)
	}
	if descriptors == nil {
		return sarifDescriptorSet{}, fmt.Errorf("%s must be an array", property)
	}
	set.descriptors = make([]sarifReportingDescriptor, len(descriptors))
	for index, rawDescriptor := range descriptors {
		descriptor, err := parseSARIFReportingDescriptor(rawDescriptor, fmt.Sprintf("%s %d", label, index), parseConfiguration)
		if err != nil {
			return sarifDescriptorSet{}, err
		}
		set.descriptors[index] = descriptor
		set.descriptorsByID[descriptor.id] = append(set.descriptorsByID[descriptor.id], index)
		if descriptor.guid != "" {
			set.descriptorsByGUID[descriptor.guid] = append(set.descriptorsByGUID[descriptor.guid], index)
		}
	}
	return set, nil
}

func parseSARIFReportingDescriptor(raw json.RawMessage, label string, parseConfiguration bool) (sarifReportingDescriptor, error) {
	object, err := decodeJSONObject(raw, label)
	if err != nil {
		return sarifReportingDescriptor{}, err
	}
	id, exists, err := sarifStringProperty(object, "id")
	if err != nil || !exists || id == "" {
		return sarifReportingDescriptor{}, fmt.Errorf("%s id must be a nonempty string", label)
	}
	guid, _, err := sarifGUIDProperty(object)
	if err != nil {
		return sarifReportingDescriptor{}, fmt.Errorf("%s: %w", label, err)
	}
	// §§3.49.14 and 3.50.3 default an unspecified descriptor configuration level to warning.
	descriptor := sarifReportingDescriptor{id: id, guid: guid, defaultLevel: sarifLevelWarning}
	if !parseConfiguration {
		return descriptor, nil
	}
	if configurationRaw, exists := object["defaultConfiguration"]; exists {
		configuration, err := decodeJSONObject(configurationRaw, label+" defaultConfiguration")
		if err != nil {
			return sarifReportingDescriptor{}, err
		}
		if level, exists, err := sarifLevelProperty(configuration); err != nil {
			return sarifReportingDescriptor{}, fmt.Errorf("%s defaultConfiguration: %w", label, err)
		} else if exists {
			descriptor.defaultLevel = level
		}
	}
	return descriptor, nil
}

func (resolver *sarifNotificationResolver) notificationOverrides(invocation map[string]json.RawMessage) (map[sarifDescriptorKey]string, error) {
	overrides := make(map[sarifDescriptorKey]string)
	raw, exists := invocation["notificationConfigurationOverrides"]
	if !exists {
		return overrides, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("decode notificationConfigurationOverrides: %w", err)
	}
	if entries == nil {
		return nil, errors.New("notificationConfigurationOverrides must be an array")
	}
	for index, rawEntry := range entries {
		entry, err := decodeJSONObject(rawEntry, fmt.Sprintf("notificationConfigurationOverrides[%d]", index))
		if err != nil {
			return nil, err
		}
		// §§3.51.2 and 3.51.3 require both descriptor and configuration.
		descriptorRaw, exists := entry["descriptor"]
		if !exists {
			return nil, fmt.Errorf("notificationConfigurationOverrides[%d] has no descriptor", index)
		}
		resolution, err := resolver.resolveDescriptor(descriptorRaw, sarifNotificationDescriptors)
		if err != nil {
			return nil, fmt.Errorf("notificationConfigurationOverrides[%d] descriptor: %w", index, err)
		}
		if resolution.descriptor == nil {
			return nil, fmt.Errorf("notificationConfigurationOverrides[%d] descriptor has no metadata", index)
		}
		configurationRaw, exists := entry["configuration"]
		if !exists {
			return nil, fmt.Errorf("notificationConfigurationOverrides[%d] has no configuration", index)
		}
		configuration, err := decodeJSONObject(configurationRaw, fmt.Sprintf("notificationConfigurationOverrides[%d] configuration", index))
		if err != nil {
			return nil, err
		}
		level, _, err := sarifLevelProperty(configuration)
		if err != nil {
			return nil, fmt.Errorf("notificationConfigurationOverrides[%d] configuration: %w", index, err)
		}
		if _, duplicate := overrides[resolution.key]; duplicate {
			return nil, fmt.Errorf("notificationConfigurationOverrides[%d] is ambiguous for its descriptor", index)
		}
		overrides[resolution.key] = level
	}
	return overrides, nil
}

func (resolver *sarifNotificationResolver) rejectErrorNotifications(invocation map[string]json.RawMessage, property string, overrides map[sarifDescriptorKey]string) error {
	raw, exists := invocation[property]
	if !exists {
		return nil
	}
	var notifications []json.RawMessage
	if err := json.Unmarshal(raw, &notifications); err != nil {
		return fmt.Errorf("decode %s: %w", property, err)
	}
	if notifications == nil {
		return fmt.Errorf("%s must be an array", property)
	}
	for index, rawNotification := range notifications {
		level, err := resolver.notificationLevel(rawNotification, property, index, overrides)
		if err != nil {
			return err
		}
		if level == sarifLevelError {
			return fmt.Errorf("%s[%d] has effective level error", property, index)
		}
	}
	return nil
}

func (resolver *sarifNotificationResolver) notificationLevel(raw json.RawMessage, property string, index int, overrides map[sarifDescriptorKey]string) (string, error) {
	label := fmt.Sprintf("%s[%d]", property, index)
	notification, err := decodeJSONObject(raw, label)
	if err != nil {
		return "", err
	}
	// OASIS SARIF 2.1.0 + Errata 01 §§3.11.2 and 3.11.8-3.11.11 define message validity.
	if err := validateSARIFNotificationMessage(notification["message"], label+".message"); err != nil {
		return "", err
	}
	resolution, hasResolution, err := resolver.notificationDescriptor(notification, label)
	if err != nil {
		return "", err
	}
	// §§3.58.3 and 3.52.3 resolve associatedRule against toolComponent.rules.
	if associatedRuleRaw, exists := notification["associatedRule"]; exists {
		if _, err := resolver.resolveDescriptor(associatedRuleRaw, sarifRuleDescriptors); err != nil {
			return "", fmt.Errorf("%s.associatedRule: %w", label, err)
		}
	}
	level, explicit, err := sarifLevelProperty(notification)
	if err != nil {
		return "", fmt.Errorf("%s: %w", label, err)
	}
	if explicit {
		return level, nil
	}
	return effectiveDescriptorLevel(resolution, hasResolution, overrides), nil
}

func (resolver *sarifNotificationResolver) notificationDescriptor(notification map[string]json.RawMessage, label string) (sarifDescriptorResolution, bool, error) {
	descriptorRaw, exists := notification["descriptor"]
	if !exists {
		return sarifDescriptorResolution{}, false, nil
	}
	resolved, err := resolver.resolveDescriptor(descriptorRaw, sarifNotificationDescriptors)
	if err != nil {
		return sarifDescriptorResolution{}, false, fmt.Errorf("%s.descriptor: %w", label, err)
	}
	return resolved, true, nil
}

func effectiveDescriptorLevel(resolution sarifDescriptorResolution, present bool, overrides map[sarifDescriptorKey]string) string {
	// §§3.58.6 and 3.27.10 resolve an omitted level through the matching
	// invocation override, then descriptor defaultConfiguration, then warning.
	if !present || resolution.descriptor == nil {
		return sarifLevelWarning
	}
	if override, exists := overrides[resolution.key]; exists && override != "" {
		return override
	}
	return resolution.descriptor.defaultLevel
}

type sarifDescriptorReference struct {
	id       string
	hasID    bool
	guid     string
	hasGUID  bool
	index    int
	hasIndex bool
	object   map[string]json.RawMessage
}

func (resolver *sarifNotificationResolver) resolveDescriptor(raw json.RawMessage, kind sarifDescriptorKind) (sarifDescriptorResolution, error) {
	reference, err := parseSARIFDescriptorReference(raw)
	if err != nil {
		return sarifDescriptorResolution{}, err
	}
	// §3.52.1 permits an id-only reference when no reportingDescriptor metadata
	// exists. Per §3.52.4, id does not participate in descriptor lookup.
	if !reference.hasIndex && !reference.hasGUID {
		if len(reference.object) != 1 {
			return sarifDescriptorResolution{}, errors.New("id-only reportingDescriptorReference must contain only id")
		}
		// §3.52.2 requires index or guid when matching descriptor metadata is present.
		// The ID index detects that condition but never selects the descriptor (§3.52.4).
		if resolver.driver.descriptorSet(kind).hasDescriptorID(reference.id) {
			return sarifDescriptorResolution{}, errors.New("id-only reportingDescriptorReference matches metadata and requires index or guid")
		}
		return sarifDescriptorResolution{}, nil
	}

	componentIndex := -1
	if componentRaw, exists := reference.object["toolComponent"]; exists {
		componentIndex, err = resolver.resolveComponent(componentRaw)
		if err != nil {
			return sarifDescriptorResolution{}, err
		}
	}
	component := resolver.component(componentIndex)
	set := component.descriptorSet(kind)
	descriptorIndex, err := resolveDescriptorIndex(set, reference)
	if err != nil {
		return sarifDescriptorResolution{}, err
	}
	return sarifDescriptorResolution{
		key:        sarifDescriptorKey{component: componentIndex, descriptor: descriptorIndex},
		descriptor: &set.descriptors[descriptorIndex],
	}, nil
}

func parseSARIFDescriptorReference(raw json.RawMessage) (sarifDescriptorReference, error) {
	object, err := decodeJSONObject(raw, "reportingDescriptorReference")
	if err != nil {
		return sarifDescriptorReference{}, err
	}
	id, hasID, err := sarifStringProperty(object, "id")
	if err != nil || hasID && id == "" {
		return sarifDescriptorReference{}, errors.New("reportingDescriptorReference id must be a nonempty string")
	}
	guid, hasGUID, err := sarifGUIDProperty(object)
	if err != nil {
		return sarifDescriptorReference{}, fmt.Errorf("reportingDescriptorReference: %w", err)
	}
	index, hasIndex, err := sarifIndexProperty(object, "index")
	if err != nil {
		return sarifDescriptorReference{}, err
	}
	if !hasID && !hasGUID && !hasIndex {
		return sarifDescriptorReference{}, errors.New("reportingDescriptorReference has no id, index, or guid")
	}
	return sarifDescriptorReference{id: id, hasID: hasID, guid: guid, hasGUID: hasGUID, index: index, hasIndex: hasIndex, object: object}, nil
}

func resolveDescriptorIndex(set *sarifDescriptorSet, reference sarifDescriptorReference) (int, error) {
	candidates := make(map[int]struct{})
	if reference.hasGUID {
		for _, candidate := range set.descriptorsByGUID[reference.guid] {
			candidates[candidate] = struct{}{}
		}
		if len(candidates) == 0 {
			return 0, errors.New("reportingDescriptorReference does not resolve")
		}
		if len(candidates) != 1 {
			return 0, errors.New("reportingDescriptorReference is ambiguous")
		}
	}
	if err := selectDescriptorIndex(set, reference, candidates); err != nil {
		return 0, err
	}
	for candidate := range candidates {
		if reference.hasID && !sarifDescriptorIDMatches(reference.id, set.descriptors[candidate].id) {
			delete(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return 0, errors.New("reportingDescriptorReference does not resolve")
	}
	if len(candidates) != 1 {
		return 0, errors.New("reportingDescriptorReference is ambiguous")
	}
	for descriptorIndex := range candidates {
		return descriptorIndex, nil
	}
	panic("unreachable")
}

func selectDescriptorIndex(set *sarifDescriptorSet, reference sarifDescriptorReference, candidates map[int]struct{}) error {
	if !reference.hasIndex {
		return nil
	}
	if reference.index >= len(set.descriptors) {
		return errors.New("reportingDescriptorReference does not resolve")
	}
	if reference.hasGUID {
		if _, agrees := candidates[reference.index]; !agrees {
			return errors.New("reportingDescriptorReference does not resolve")
		}
	}
	clear(candidates)
	candidates[reference.index] = struct{}{}
	return nil
}

// OASIS SARIF 2.1.0 + Errata 01 §3.54.2 uses index/guid for component lookup;
// name is only a consistency field (§3.54.3).
func (resolver *sarifNotificationResolver) resolveComponent(raw json.RawMessage) (int, error) {
	reference, err := decodeJSONObject(raw, "toolComponentReference")
	if err != nil {
		return 0, err
	}
	name, hasName, err := sarifStringProperty(reference, "name")
	if err != nil || hasName && name == "" {
		return 0, errors.New("toolComponentReference name must be a nonempty string")
	}
	guid, hasGUID, err := sarifGUIDProperty(reference)
	if err != nil {
		return 0, fmt.Errorf("toolComponentReference: %w", err)
	}
	index, hasIndex, err := sarifIndexProperty(reference, "index")
	if err != nil {
		return 0, err
	}

	componentIndex := -1
	if hasGUID {
		matches := resolver.componentsByGUID[guid]
		if len(matches) == 0 {
			return 0, errors.New("toolComponentReference does not resolve")
		}
		if len(matches) != 1 {
			return 0, errors.New("toolComponentReference is ambiguous")
		}
		componentIndex = matches[0]
	}
	if hasIndex {
		if index >= len(resolver.extensions) {
			return 0, errors.New("toolComponentReference does not resolve")
		}
		if hasGUID && componentIndex != index {
			return 0, errors.New("toolComponentReference does not resolve")
		}
		componentIndex = index
	}
	component := resolver.component(componentIndex)
	if hasName && component.name != name || hasGUID && component.guid != guid {
		return 0, errors.New("toolComponentReference does not resolve")
	}
	return componentIndex, nil
}

func (resolver *sarifNotificationResolver) component(index int) *sarifNotificationComponent {
	if index < 0 {
		return &resolver.driver
	}
	return &resolver.extensions[index]
}

func (component *sarifNotificationComponent) descriptorSet(kind sarifDescriptorKind) *sarifDescriptorSet {
	if kind == sarifRuleDescriptors {
		return &component.rules
	}
	return &component.notifications
}

func (set *sarifDescriptorSet) hasDescriptorID(referenceID string) bool {
	for descriptorID := range set.descriptorsByID {
		if sarifDescriptorIDMatches(referenceID, descriptorID) {
			return true
		}
	}
	return false
}

func validateSARIFNotificationMessage(raw json.RawMessage, label string) error {
	message, err := decodeJSONObject(raw, label)
	if err != nil {
		return err
	}
	if err := validateSARIFMessageProperties(message, label); err != nil {
		return err
	}
	if err := validateSARIFMessageText(message, label); err != nil {
		return err
	}
	return validateSARIFMessageCollections(message, label)
}

func validateSARIFMessageProperties(message map[string]json.RawMessage, label string) error {
	// The Errata 01 normative message schema sets additionalProperties to false.
	for property := range message {
		switch property {
		case "text", "markdown", "id", "arguments", "properties":
		default:
			return fmt.Errorf("%s has unsupported property %q", label, property)
		}
	}
	return nil
}

func validateSARIFMessageText(message map[string]json.RawMessage, label string) error {
	text, hasText, err := sarifStringProperty(message, "text")
	if err != nil || hasText && text == "" {
		return fmt.Errorf("%s.text must be a nonempty string", label)
	}
	id, hasID, err := sarifStringProperty(message, "id")
	if err != nil || hasID && id == "" {
		return fmt.Errorf("%s.id must be a nonempty string", label)
	}
	if !hasText && !hasID {
		return fmt.Errorf("%s must contain text or id", label)
	}
	markdown, hasMarkdown, err := sarifStringProperty(message, "markdown")
	if err != nil || hasMarkdown && markdown == "" {
		return fmt.Errorf("%s.markdown must be a nonempty string", label)
	}
	if hasMarkdown && !hasText {
		return fmt.Errorf("%s.markdown requires text", label)
	}
	return nil
}

func validateSARIFMessageCollections(message map[string]json.RawMessage, label string) error {
	if argumentsRaw, exists := message["arguments"]; exists {
		var arguments []string
		if err := json.Unmarshal(argumentsRaw, &arguments); err != nil || arguments == nil {
			return fmt.Errorf("%s.arguments must be an array of strings", label)
		}
	}
	if propertiesRaw, exists := message["properties"]; exists {
		if err := requireJSONObjectAllowEmpty(propertiesRaw, label+".properties"); err != nil {
			return err
		}
	}
	return nil
}

func sarifStringProperty(object map[string]json.RawMessage, property string) (string, bool, error) {
	raw, exists := object[property]
	if !exists {
		return "", false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", true, fmt.Errorf("%s must be a string", property)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, fmt.Errorf("%s must be a string", property)
	}
	return value, true, nil
}

func sarifIndexProperty(object map[string]json.RawMessage, property string) (int, bool, error) {
	raw, exists := object[property]
	if !exists {
		return 0, false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, true, fmt.Errorf("%s must be a nonnegative integer", property)
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil || value < 0 {
		return 0, true, fmt.Errorf("%s must be a nonnegative integer", property)
	}
	return value, true, nil
}

func sarifGUIDProperty(object map[string]json.RawMessage) (string, bool, error) {
	guid, exists, err := sarifStringProperty(object, "guid")
	if err != nil {
		return "", exists, err
	}
	if exists && !sarifGUIDPattern.MatchString(guid) {
		return "", true, errors.New("guid must match the SARIF GUID pattern")
	}
	return guid, exists, nil
}

func sarifLevelProperty(object map[string]json.RawMessage) (string, bool, error) {
	level, exists, err := sarifStringProperty(object, "level")
	if err != nil {
		return "", exists, err
	}
	if !exists {
		return "", false, nil
	}
	switch level {
	case "none", "note", sarifLevelWarning, sarifLevelError:
		return level, true, nil
	default:
		return "", true, fmt.Errorf("unsupported level %q", level)
	}
}

func sarifDescriptorIDMatches(referenceID, descriptorID string) bool {
	if referenceID == descriptorID {
		return true
	}
	suffix := strings.TrimPrefix(referenceID, descriptorID+"/")
	return suffix != referenceID && suffix != "" && !strings.ContainsRune(suffix, '/')
}
