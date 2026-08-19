#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

go generate ./...
git diff --exit-code -- generated
untracked=$(git ls-files --others --exclude-standard -- generated)
test -z "$untracked"
