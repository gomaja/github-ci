package reports

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gomaja/github-ci/internal/pathpolicy"
)

func countActionlint(data []byte) (int, error) {
	var findings []struct {
		Message   string `json:"message"`
		Filepath  string `json:"filepath"`
		Line      int    `json:"line"`
		Column    int    `json:"column"`
		Kind      string `json:"kind"`
		Snippet   string `json:"snippet"`
		EndColumn int    `json:"end_column"`
	}
	if err := decodeStrictJSON(data, &findings); err != nil {
		return 0, err
	}
	if findings == nil {
		return 0, errors.New("actionlint report must be a JSON array")
	}
	for index, finding := range findings {
		if strings.TrimSpace(finding.Message) == "" || strings.TrimSpace(finding.Kind) == "" || strings.TrimSpace(finding.Snippet) == "" {
			return 0, fmt.Errorf("actionlint finding %d is incomplete", index)
		}
		if err := pathpolicy.Validate("actionlint filepath", finding.Filepath); err != nil {
			return 0, fmt.Errorf("actionlint finding %d: %w", index, err)
		}
		if finding.Line <= 0 || finding.Column <= 0 || finding.EndColumn < finding.Column {
			return 0, fmt.Errorf("actionlint finding %d has invalid location", index)
		}
	}
	return len(findings), nil
}

func countSPDX(data []byte) (int, error) {
	var document struct {
		SPDXVersion          string            `json:"spdxVersion"`
		DataLicense          string            `json:"dataLicense"`
		SPDXID               string            `json:"SPDXID"`
		Name                 string            `json:"name"`
		DocumentNamespace    string            `json:"documentNamespace"`
		CreationInfo         json.RawMessage   `json:"creationInfo"`
		Packages             []json.RawMessage `json:"packages,omitempty"`
		Files                []json.RawMessage `json:"files,omitempty"`
		Relationships        []json.RawMessage `json:"relationships,omitempty"`
		DocumentDescribes    []string          `json:"documentDescribes,omitempty"`
		Annotations          []json.RawMessage `json:"annotations,omitempty"`
		ExternalDocumentRefs []json.RawMessage `json:"externalDocumentRefs,omitempty"`
	}
	if err := decodeStrictJSON(data, &document); err != nil {
		return 0, err
	}
	if document.SPDXVersion != "SPDX-2.3" || document.DataLicense != "CC0-1.0" || document.SPDXID != "SPDXRef-DOCUMENT" {
		return 0, errors.New("unsupported SPDX document identity")
	}
	if strings.TrimSpace(document.Name) == "" || strings.TrimSpace(document.DocumentNamespace) == "" {
		return 0, errors.New("SPDX document has no name or namespace")
	}
	creation, err := decodeJSONObject(document.CreationInfo, "SPDX creationInfo")
	if err != nil {
		return 0, err
	}
	if len(creation["created"]) == 0 || len(creation["creators"]) == 0 {
		return 0, errors.New("SPDX creationInfo is incomplete")
	}
	if len(document.Packages)+len(document.Files) == 0 {
		return 0, errors.New("SPDX document has no described subject")
	}
	describesSubject := len(document.DocumentDescribes) != 0
	for index, raw := range document.Relationships {
		var relationship struct {
			SPDXElementID      string `json:"spdxElementId"`
			RelationshipType   string `json:"relationshipType"`
			RelatedSPDXElement string `json:"relatedSpdxElement"`
			Comment            string `json:"comment,omitempty"`
		}
		if err := decodeStrictJSON(raw, &relationship); err != nil {
			return 0, fmt.Errorf("SPDX relationship %d: %w", index, err)
		}
		if relationship.SPDXElementID == "SPDXRef-DOCUMENT" && relationship.RelationshipType == "DESCRIBES" && relationship.RelatedSPDXElement != "" {
			describesSubject = true
		}
	}
	if !describesSubject {
		return 0, errors.New("SPDX document has no described subject")
	}
	for _, group := range [][]json.RawMessage{document.Packages, document.Files, document.Relationships, document.Annotations, document.ExternalDocumentRefs} {
		if err := validateObjects(group, "SPDX entry"); err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func countLicenseInventory(data []byte) (int, error) {
	type dependency struct {
		Package string `json:"package"`
		License string `json:"license"`
	}
	type violation struct {
		Package string `json:"package"`
		License string `json:"license"`
		Reason  string `json:"reason"`
	}
	var inventory struct {
		SchemaVersion string       `json:"schema_version"`
		Dependencies  []dependency `json:"dependencies"`
		Violations    []violation  `json:"violations"`
	}
	if err := decodeStrictJSON(data, &inventory); err != nil {
		return 0, err
	}
	if inventory.SchemaVersion != "1" {
		return 0, fmt.Errorf("unsupported license inventory schema %q", inventory.SchemaVersion)
	}
	if inventory.Dependencies == nil || inventory.Violations == nil {
		return 0, errors.New("license inventory arrays must not be null")
	}
	for index, dependency := range inventory.Dependencies {
		if strings.TrimSpace(dependency.Package) == "" || strings.TrimSpace(dependency.License) == "" {
			return 0, fmt.Errorf("license dependency %d is incomplete", index)
		}
	}
	for index, violation := range inventory.Violations {
		if strings.TrimSpace(violation.Package) == "" || strings.TrimSpace(violation.License) == "" || strings.TrimSpace(violation.Reason) == "" {
			return 0, fmt.Errorf("license violation %d is incomplete", index)
		}
	}
	return len(inventory.Violations), nil
}
