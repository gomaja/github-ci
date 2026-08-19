// Package canary exercises the complete schema 2 workflow contract.
package canary

//go:generate go run ./internal/generate

// RootMarker is present only when both canary build tags are applied.
const RootMarker = taggedRootMarker
