#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_CI_CLI:?}"
: "${PLAN_PATH:?}"
: "${EVIDENCE_DIR:?}"
: "${FORMAT_RESULT:?}"
: "${CORE_RESULT:?}"
: "${TEST_RESULT:?}"
: "${ANALYSIS_RESULT:?}"
: "${CODEQL_RESULT:?}"
: "${DEPENDENCY_RESULT:?}"
: "${SECURITY_RESULT:?}"
: "${SUPPLY_CHAIN_RESULT:?}"
: "${REPOSITORY_RESULT:?}"
: "${SCORECARD_RESULT:?}"

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
	if ! jq -e --arg tool "$tool" --arg command "$command_id" \
		'.expected[] | select(.tool == $tool and .command_id == $command)' "$PLAN_PATH" >/dev/null; then
		return
	fi
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
add_producer codeql codeql/actions "$CODEQL_RESULT"
add_producer codeql codeql/go "$CODEQL_RESULT"
add_producer dependency-review dependency-review/changes "$DEPENDENCY_RESULT"
add_producer gitleaks gitleaks/content "$SECURITY_RESULT"
add_producer osv-scanner osv-scanner/dependencies "$SECURITY_RESULT"
add_producer trivy trivy/filesystem "$SECURITY_RESULT"
add_producer semgrep semgrep/source "$SECURITY_RESULT"
add_producer syft syft/sbom "$SUPPLY_CHAIN_RESULT"
add_producer grype grype/sbom "$SUPPLY_CHAIN_RESULT"
add_producer license license/dependencies "$SUPPLY_CHAIN_RESULT"
add_producer apidiff apidiff/public-api "$SUPPLY_CHAIN_RESULT"
add_producer actionlint actionlint/workflows "$REPOSITORY_RESULT"
add_producer zizmor zizmor/workflows "$REPOSITORY_RESULT"
add_producer hadolint hadolint/dockerfiles "$REPOSITORY_RESULT"
add_producer bash bash/scripts "$REPOSITORY_RESULT"
add_producer shellcheck shellcheck/scripts "$REPOSITORY_RESULT"
add_producer shfmt shfmt/scripts "$REPOSITORY_RESULT"
add_producer yamllint yamllint/documents "$REPOSITORY_RESULT"
add_producer markdownlint markdownlint/documents "$REPOSITORY_RESULT"
add_producer json json/documents "$REPOSITORY_RESULT"
add_producer checkov checkov/infrastructure "$REPOSITORY_RESULT"
add_producer repository repository/hygiene "$REPOSITORY_RESULT"
add_producer generated generated/files "$REPOSITORY_RESULT"
add_producer scorecard scorecard/repository "$SCORECARD_RESULT"

jq -s '{schema_version:"1",producers:.}' "$entries" >"$output"
