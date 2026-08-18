#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_CI_CLI:?}"
: "${PLAN_PATH:?}"
: "${OUTPUT_DIR:?}"
: "${TOOL:?}"
: "${COMMAND_ID:?}"
: "${TOOL_VERSION:?}"

records="$OUTPUT_DIR/records"
reports="$OUTPUT_DIR/reports"
mkdir -p "$records" "$reports"
name="${TOOL}--${COMMAND_ID}"
name=${name//\//--}
record="$records/$name.json"

set +e
"$GITHUB_CI_CLI" applicable --plan "$PLAN_PATH" --tool "$TOOL" --command-id "$COMMAND_ID"
applicability=$?
set -e
if ((applicability == 1)); then
	"$GITHUB_CI_CLI" record --plan "$PLAN_PATH" --tool "$TOOL" --command-id "$COMMAND_ID" \
		--tool-version "$TOOL_VERSION" --output "$record"
	exit 0
fi
((applicability == 0)) || exit "$applicability"

: "${REPORT_PATH:?}"
[[ -s "$REPORT_PATH" ]] || {
	printf 'native report is missing: %s\n' "$REPORT_PATH" >&2
	exit 2
}

set +e
"$GITHUB_CI_CLI" record --plan "$PLAN_PATH" --tool "$TOOL" --command-id "$COMMAND_ID" \
	--tool-version "$TOOL_VERSION" --report "$REPORT_PATH" --exit-code "${PRODUCER_EXIT_CODE:-0}" --output "$record"
status=$?
set -e
((status <= 1)) || exit "$status"
