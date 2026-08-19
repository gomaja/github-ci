#!/usr/bin/env bash
set -euo pipefail

go generate ./...
git diff --exit-code -- generated
untracked=$(git ls-files --others --exclude-standard -- generated)
test -z "$untracked"
