package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxEvidenceBytes = 67_108_864

// Read decodes and validates exactly one bounded evidence record.
func Read(reader io.Reader) (Record, error) {
	if reader == nil {
		return Record{}, errors.New("evidence reader is nil")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxEvidenceBytes+1))
	if err != nil {
		return Record{}, fmt.Errorf("read evidence: %w", err)
	}
	if len(data) == 0 {
		return Record{}, errors.New("empty evidence")
	}
	if len(data) > maxEvidenceBytes {
		return Record{}, fmt.Errorf("evidence exceeds %d byte limit", maxEvidenceBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record Record
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fmt.Errorf("decode evidence: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Record{}, errors.New("evidence contains a trailing JSON value")
		}
		return Record{}, fmt.Errorf("decode trailing evidence: %w", err)
	}
	if err := ValidateRecord(record); err != nil {
		return Record{}, fmt.Errorf("validate evidence: %w", err)
	}
	return record, nil
}

// WriteAtomic validates and durably replaces one evidence file.
func WriteAtomic(filename string, record Record) error {
	if err := ValidateRecord(record); err != nil {
		return fmt.Errorf("validate evidence: %w", err)
	}
	data, err := record.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}
	data = append(data, '\n')

	directory := filepath.Dir(filename)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(filename)+"-*")
	if err != nil {
		return fmt.Errorf("create temporary evidence: %w", err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temporary.Close()
			_ = os.Remove(temporaryName)
		}
	}()

	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("set temporary evidence permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary evidence: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary evidence: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary evidence: %w", err)
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("replace evidence: %w", err)
	}
	committed = true
	return nil
}
