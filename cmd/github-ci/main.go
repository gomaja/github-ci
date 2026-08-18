// Package main runs the github-ci assurance command.
package main

import (
	"context"
	"os"
	"time"

	"github.com/gomaja/github-ci/internal/command"
)

func main() {
	os.Exit(command.Run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, time.Now))
}
