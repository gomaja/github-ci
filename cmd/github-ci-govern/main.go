// Package main runs the github-ci repository governance command.
package main

import (
	"context"
	"os"

	"github.com/gomaja/github-ci/internal/governance"
)

func main() {
	os.Exit(governance.RunCLI(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
