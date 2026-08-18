package reports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type sarifNotificationResolver struct {
	driver           sarifNotificationComponent
	extensions       []sarifNotificationComponent
	componentsByGUID map[string][]int
}

type sarifNotificationComponent struct {
	name              string
	guid              string
	descriptors       []sarifNotificationDescriptor
	descriptorsByID   map[string][]int
	descriptorsByGUID map[string][]int
}

type sarifNotificationDescriptor struct {
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
	descriptor *sarifNotificationDescriptor
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
	guid, _, err := sarifStringProperty(object, "guid")
	if err != nil {
		return sarifNotificationComponent{}, fmt.Errorf("SARIF %s: %w", label, err)
	}
	component := sarifNotificationComponent{
		name:              name,
		guid:              guid,
		descriptorsByID:   make(map[string][]int),
		descriptorsByGUID: make(map[string][]int),
	}
	notificationsRaw, exists := object["notifications"]
	if !exists {
		return component, nil
	}
	var notifications []json.RawMessage
	if err := json.Unmarshal(notificationsRaw, &notifications); err != nil {
		return sarifNotificationComponent{}, fmt.Errorf("decode SARIF %s notifications: %w", label, err)
	}
	if notifications == nil {
		return sarifNotificationComponent{}, fmt.Errorf("SARIF %s notifications must be an array", label)
	}
	component.descriptors = make([]sarifNotificationDescriptor, len(notifications))
	for index, rawDescriptor := range notifications {
		descriptor, err := parseSARIFNotificationDescriptor(rawDescriptor, fmt.Sprintf("SARIF %s notification descriptor %d", label, index))
		if err != nil {
			return sarifNotificationComponent{}, err
		}
		component.descriptors[index] = descriptor
		component.descriptorsByID[descriptor.id] = append(component.descriptorsByID[descriptor.id], index)
		if descriptor.guid != "" {
			component.descriptorsByGUID[descriptor.guid] = append(component.descriptorsByGUID[descriptor.guid], index)
		}
	}
	return component, nil
}

func parseSARIFNotificationDescriptor(raw json.RawMessage, label string) (sarifNotificationDescriptor, error) {
	object, err := decodeJSONObject(raw, label)
	if err != nil {
		return sarifNotificationDescriptor{}, err
	}
	id, exists, err := sarifStringProperty(object, "id")
	if err != nil || !exists || id == "" {
		return sarifNotificationDescriptor{}, fmt.Errorf("%s id must be a nonempty string", label)
	}
	guid, _, err := sarifStringProperty(object, "guid")
	if err != nil {
		return sarifNotificationDescriptor{}, fmt.Errorf("%s: %w", label, err)
	}
	// §§3.49.14 and 3.50.3 default an unspecified descriptor configuration level to warning.
	descriptor := sarifNotificationDescriptor{id: id, guid: guid, defaultLevel: "warning"}
	if configurationRaw, exists := object["defaultConfiguration"]; exists {
		configuration, err := decodeJSONObject(configurationRaw, label+" defaultConfiguration")
		if err != nil {
			return sarifNotificationDescriptor{}, err
		}
		if level, exists, err := sarifLevelProperty(configuration); err != nil {
			return sarifNotificationDescriptor{}, fmt.Errorf("%s defaultConfiguration: %w", label, err)
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
		resolution, err := resolver.resolveDescriptor(descriptorRaw)
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
		notification, err := decodeJSONObject(rawNotification, fmt.Sprintf("%s[%d]", property, index))
		if err != nil {
			return err
		}
		// OASIS SARIF 2.1.0 + Errata 01 §3.58.5 requires a nonempty message object.
		if err := requireJSONObject(notification["message"], fmt.Sprintf("%s[%d].message", property, index)); err != nil {
			return err
		}

		var resolution *sarifDescriptorResolution
		if descriptorRaw, exists := notification["descriptor"]; exists {
			resolved, err := resolver.resolveDescriptor(descriptorRaw)
			if err != nil {
				return fmt.Errorf("%s[%d].descriptor: %w", property, index, err)
			}
			resolution = &resolved
		}

		level, explicit, err := sarifLevelProperty(notification)
		if err != nil {
			return fmt.Errorf("%s[%d]: %w", property, index, err)
		}
		// §§3.58.6 and 3.27.10 resolve an omitted level through the matching
		// invocation override, then descriptor defaultConfiguration, then warning.
		if !explicit {
			level = "warning"
			if resolution != nil && resolution.descriptor != nil {
				if override, exists := overrides[resolution.key]; exists && override != "" {
					level = override
				} else {
					level = resolution.descriptor.defaultLevel
				}
			}
		}
		if level == "error" {
			return fmt.Errorf("%s[%d] has effective level error", property, index)
		}
	}
	return nil
}

func (resolver *sarifNotificationResolver) resolveDescriptor(raw json.RawMessage) (sarifDescriptorResolution, error) {
	reference, err := decodeJSONObject(raw, "reportingDescriptorReference")
	if err != nil {
		return sarifDescriptorResolution{}, err
	}
	id, hasID, err := sarifStringProperty(reference, "id")
	if err != nil || hasID && id == "" {
		return sarifDescriptorResolution{}, errors.New("reportingDescriptorReference id must be a nonempty string")
	}
	guid, hasGUID, err := sarifStringProperty(reference, "guid")
	if err != nil || hasGUID && guid == "" {
		return sarifDescriptorResolution{}, errors.New("reportingDescriptorReference guid must be a nonempty string")
	}
	index, hasIndex, err := sarifIndexProperty(reference, "index")
	if err != nil {
		return sarifDescriptorResolution{}, err
	}
	if !hasID && !hasGUID && !hasIndex {
		return sarifDescriptorResolution{}, errors.New("reportingDescriptorReference has no id, index, or guid")
	}
	// §3.52.1 permits an id-only reference when no reportingDescriptor metadata
	// exists. Per §3.52.4, id does not participate in descriptor lookup.
	if !hasIndex && !hasGUID {
		if len(reference) != 1 {
			return sarifDescriptorResolution{}, errors.New("id-only reportingDescriptorReference must contain only id")
		}
		// §3.52.2 requires index or guid when matching descriptor metadata is present.
		// The ID index detects that condition but never selects the descriptor (§3.52.4).
		if resolver.driver.hasDescriptorID(id) {
			return sarifDescriptorResolution{}, errors.New("id-only reportingDescriptorReference matches metadata and requires index or guid")
		}
		return sarifDescriptorResolution{}, nil
	}

	componentIndex := -1
	if componentRaw, exists := reference["toolComponent"]; exists {
		componentIndex, err = resolver.resolveComponent(componentRaw)
		if err != nil {
			return sarifDescriptorResolution{}, err
		}
	}
	component := resolver.component(componentIndex)
	candidates := make(map[int]struct{})
	if hasGUID {
		for _, candidate := range component.descriptorsByGUID[guid] {
			candidates[candidate] = struct{}{}
		}
		if len(candidates) == 0 {
			return sarifDescriptorResolution{}, errors.New("reportingDescriptorReference does not resolve")
		}
		if len(candidates) != 1 {
			return sarifDescriptorResolution{}, errors.New("reportingDescriptorReference is ambiguous")
		}
	}
	if hasIndex {
		if index >= len(component.descriptors) {
			return sarifDescriptorResolution{}, errors.New("reportingDescriptorReference does not resolve")
		}
		if hasGUID {
			if _, agrees := candidates[index]; !agrees {
				return sarifDescriptorResolution{}, errors.New("reportingDescriptorReference does not resolve")
			}
		}
		clear(candidates)
		candidates[index] = struct{}{}
	}
	for candidate := range candidates {
		descriptor := &component.descriptors[candidate]
		// §§3.52.2-3.52.6 use index/guid for lookup; id only checks the located metadata.
		if hasID && !sarifDescriptorIDMatches(id, descriptor.id) {
			delete(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return sarifDescriptorResolution{}, errors.New("reportingDescriptorReference does not resolve")
	}
	if len(candidates) != 1 {
		return sarifDescriptorResolution{}, errors.New("reportingDescriptorReference is ambiguous")
	}
	for descriptorIndex := range candidates {
		return sarifDescriptorResolution{
			key:        sarifDescriptorKey{component: componentIndex, descriptor: descriptorIndex},
			descriptor: &component.descriptors[descriptorIndex],
		}, nil
	}
	panic("unreachable")
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
	guid, hasGUID, err := sarifStringProperty(reference, "guid")
	if err != nil || hasGUID && guid == "" {
		return 0, errors.New("toolComponentReference guid must be a nonempty string")
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

func (component *sarifNotificationComponent) hasDescriptorID(referenceID string) bool {
	if len(component.descriptorsByID[referenceID]) != 0 {
		return true
	}
	separator := strings.LastIndexByte(referenceID, '/')
	return separator > 0 && separator < len(referenceID)-1 && len(component.descriptorsByID[referenceID[:separator]]) != 0
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

func sarifLevelProperty(object map[string]json.RawMessage) (string, bool, error) {
	level, exists, err := sarifStringProperty(object, "level")
	if err != nil {
		return "", exists, err
	}
	if !exists {
		return "", false, nil
	}
	switch level {
	case "none", "note", "warning", "error":
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
