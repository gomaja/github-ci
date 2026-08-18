#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_CI_CLI:?}"
: "${PLAN_PATH:?}"
: "${EVIDENCE_DIR:?}"
: "${FORMAT_RESULT:?}"
: "${CORE_RESULT:?}"
: "${TEST_RESULT:?}"
: "${ANALYSIS_RESULT:?}"

output=${1:?output path is required}
entries="$EVIDENCE_DIR/manifest-entries.jsonl"
: >"$entries"

execution_for() {
	case "$1" in
	cancelled) printf cancelled ;;
	skipped) printf skipped ;;
	failure) printf failed ;;
	success) printf failed ;;
	*) printf failed ;;
	esac
}

add_producer() {
	local tool=$1 command_id=$2 group_result=$3 name record report status execution
	name="${tool}--${command_id}"
	name=${name//\//--}
	record="records/$name.json"
	report="reports/$name.native"
	set +e
	"$GITHUB_CI_CLI" applicable --plan "$PLAN_PATH" --tool "$tool" --command-id "$command_id"
	status=$?
	set -e
	if ((status == 1)); then
		jq -cn --arg tool "$tool" --arg command "$command_id" --arg record "$record" '{tool:$tool,command_id:$command,execution:"skipped",record_path:$record}' >>"$entries"
		return
	fi
	((status == 0)) || return "$status"
	if [[ -s "$EVIDENCE_DIR/$record" && -s "$EVIDENCE_DIR/$report" ]]; then
		execution=completed
	else
		execution=$(execution_for "$group_result")
	fi
	jq -cn --arg tool "$tool" --arg command "$command_id" --arg execution "$execution" --arg record "$record" --arg report "$report" '{tool:$tool,command_id:$command,execution:$execution,record_path:$record,report_path:$report}' >>"$entries"
}

add_producer gofmt gofmt/tracked-go "$FORMAT_RESULT"
add_producer goimports goimports/tracked-go "$FORMAT_RESULT"
add_producer go go/module-integrity "$CORE_RESULT"
add_producer go go/build "$CORE_RESULT"
add_producer go go/vet "$CORE_RESULT"
add_producer gopls gopls/tracked-go "$CORE_RESULT"
add_producer go go/test "$TEST_RESULT"
add_producer go go/race "$TEST_RESULT"
add_producer staticcheck staticcheck/default "$ANALYSIS_RESULT"
add_producer golangci-lint golangci-lint/default "$ANALYSIS_RESULT"
add_producer govulncheck govulncheck/modules "$ANALYSIS_RESULT"

jq -s '{schema_version:"1",producers:.}' "$entries" >"$output"
