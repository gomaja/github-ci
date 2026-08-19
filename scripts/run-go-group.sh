#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_CI_CLI:?}"
: "${SOURCE_DIR:?}"
: "${CENTRAL_DIR:?}"
: "${PLAN_PATH:?}"
: "${GO_PLAN_PATH:?}"
: "${CONFIG_PATH:?}"
: "${OUTPUT_DIR:?}"

if [[ -n ${RUNNER_TEMP:-} ]]; then
	export PATH="$RUNNER_TEMP/github-ci-bin:$PATH"
fi

group=${1:?group is required}
source "$CENTRAL_DIR/scripts/load-go-plan.sh"
records="$OUTPUT_DIR/records"
reports="$OUTPUT_DIR/reports"
parts="$OUTPUT_DIR/parts"
mkdir -p "$records" "$reports" "$parts"

load_go_modules "$GO_PLAN_PATH"
modules=("${GO_PLAN_MODULE_PATHS[@]}")

module_directory() {
	local index=$1
	if [[ "${GO_PLAN_MODULE_DIRECTORIES[$index]}" == "." ]]; then
		printf '%s' "$SOURCE_DIR"
	else
		printf '%s' "$SOURCE_DIR/${GO_PLAN_MODULE_DIRECTORIES[$index]}"
	fi
}

execute_planned() {
	local index=$1 tool=$2 directory
	shift 2
	load_go_invocation "$GO_PLAN_PATH" "$index" "$tool"
	directory=$(module_directory "$index")
	if ((${#GO_PLAN_ENVIRONMENT[@]} == 0)); then
		(cd "$directory" && "${GO_PLAN_ARGUMENTS[@]}" "$@")
	else
		(cd "$directory" && env "${GO_PLAN_ENVIRONMENT[@]}" "${GO_PLAN_ARGUMENTS[@]}" "$@")
	fi
}

safe_name() {
	printf '%s' "${1//\//--}"
}

record_result() {
	local tool=$1 command_id=$2 version=$3 report=${4:-} exit_code=${5:-0}
	local name record status
	name=$(safe_name "$tool--$command_id")
	record="$records/$name.json"
	set +e
	if [[ -n "$report" ]]; then
		"$GITHUB_CI_CLI" record --plan "$PLAN_PATH" --tool "$tool" --command-id "$command_id" --tool-version "$version" --report "$report" --exit-code "$exit_code" --output "$record"
	else
		"$GITHUB_CI_CLI" record --plan "$PLAN_PATH" --tool "$tool" --command-id "$command_id" --tool-version "$version" --output "$record"
	fi
	status=$?
	set -e
	if ((status > 1)); then
		return "$status"
	fi
	return 0
}

is_applicable() {
	local tool=$1 command_id=$2 status
	set +e
	"$GITHUB_CI_CLI" applicable --plan "$PLAN_PATH" --tool "$tool" --command-id "$command_id"
	status=$?
	set -e
	if ((status == 1)); then
		record_result "$tool" "$command_id" "$3"
		return 1
	fi
	if ((status != 0)); then
		return "$status"
	fi
	return 0
}

aggregate_parts() {
	local parser=$1 output=$2
	shift 2
	local args=() entry
	for entry in "$@"; do
		args+=(--report "$entry")
	done
	"$GITHUB_CI_CLI" aggregate --tool "$parser" "${args[@]}" --output "$output"
}

run_format() {
	local tool=$1 command_id=$2 version=$3 executable=$4
	local applicability
	set +e
	is_applicable "$tool" "$command_id" "$version"
	applicability=$?
	set -e
	if ((applicability == 1)); then
		return 0
	fi
	((applicability == 0)) || return "$applicability"
	local -a files
	while IFS= read -r -d '' file; do
		files+=("$file")
	done < <("$GITHUB_CI_CLI" files --repository "$SOURCE_DIR" --config "$CONFIG_PATH" --kind go)
	((${#files[@]} > 0)) || return 2
	local list report name
	name=$(safe_name "$tool--$command_id")
	list="$parts/$name.paths"
	report="$reports/$name.native"
	(cd "$SOURCE_DIR" && "$executable" -l "${files[@]}") >"$list"
	jq -Rn '[inputs] | {schema_version:"1", paths:.}' <"$list" >"$report"
	record_result "$tool" "$command_id" "$version" "$report" 0
}

module_files() {
	local module=$1 path candidate other include
	while IFS= read -r -d '' path; do
		include=false
		if [[ "$module" == "." ]]; then
			candidate=$path
		elif [[ "$path" == "$module/"* ]]; then
			candidate=${path#"$module/"}
		else
			continue
		fi
		include=true
		for other in "${modules[@]}"; do
			[[ "$other" == "$module" ]] && continue
			if [[ "$module" == "." && "$path" == "$other/"* ]]; then
				include=false
			elif [[ "$module" != "." && "$other" == "$module/"* && "$candidate" == "${other#"$module/"}/"* ]]; then
				include=false
			fi
		done
		[[ "$include" == true ]] && printf '%s\0' "$candidate"
	done < <("$GITHUB_CI_CLI" files --repository "$SOURCE_DIR" --config "$CONFIG_PATH" --kind all-go)
}

run_module_command() {
	local tool=$1 command_id=$2 version=$3 parser=$4
	local applicability status
	set +e
	is_applicable "$tool" "$command_id" "$version"
	applicability=$?
	set -e
	if ((applicability == 1)); then
		return 0
	fi
	((applicability == 0)) || return "$applicability"
	local overall=0 index module module_dir native name coverage
	local -a aggregate_inputs files
	name=$(safe_name "$tool--$command_id")
	for index in "${!modules[@]}"; do
		module=${modules[$index]}
		module_dir=$(module_directory "$index")
		native="$parts/$name-$index.native"
		set +e
		case "$command_id" in
		go/module-integrity)
			(cd "$module_dir" && go mod tidy -diff && go mod verify)
			status=$?
			printf '{"schema_version":"1","execution_successful":%s}\n' "$([[ $status -eq 0 ]] && printf true || printf false)" >"$native"
			;;
		go/build)
			execute_planned "$index" build
			status=$?
			printf '{"schema_version":"1","execution_successful":%s}\n' "$([[ $status -eq 0 ]] && printf true || printf false)" >"$native"
			;;
		go/vet)
			execute_planned "$index" vet
			status=$?
			printf '{"schema_version":"1","execution_successful":%s}\n' "$([[ $status -eq 0 ]] && printf true || printf false)" >"$native"
			;;
		gopls/tracked-go)
			files=()
			while IFS= read -r -d '' file; do
				files+=("$file")
			done < <(module_files "$module")
			printf '{"schema_version":"1","parser":"gopls-diagnostics-v1","execution_successful":true}\n' >"$native"
			if ((${#files[@]} == 0)); then
				status=0
			else
				execute_planned "$index" gopls "${files[@]}" >>"$native" 2>&1
				status=$?
			fi
			;;
		go/test)
			coverage="$parts/$name-$index.coverage"
			load_go_invocation "$GO_PLAN_PATH" "$index" test
			if ((${#GO_PLAN_ENVIRONMENT[@]} == 0)); then
				(cd "$module_dir" && gotestsum --format standard-quiet --junitfile "$native" -- "${GO_PLAN_ARGUMENTS[@]:2}" -coverprofile="$coverage")
			else
				(cd "$module_dir" && env "${GO_PLAN_ENVIRONMENT[@]}" gotestsum --format standard-quiet --junitfile "$native" -- "${GO_PLAN_ARGUMENTS[@]:2}" -coverprofile="$coverage")
			fi
			status=$?
			if [[ -s "$coverage" ]]; then
				gocover-cobertura <"$coverage" >"$parts/$name-$index.cobertura.xml"
			fi
			;;
		go/race)
			load_go_invocation "$GO_PLAN_PATH" "$index" race
			if ((${#GO_PLAN_ENVIRONMENT[@]} == 0)); then
				(cd "$module_dir" && gotestsum --format standard-quiet --junitfile "$native" -- "${GO_PLAN_ARGUMENTS[@]:2}")
			else
				(cd "$module_dir" && env "${GO_PLAN_ENVIRONMENT[@]}" gotestsum --format standard-quiet --junitfile "$native" -- "${GO_PLAN_ARGUMENTS[@]:2}")
			fi
			status=$?
			;;
		staticcheck/default)
			printf '{"schema_version":"1","parser":"staticcheck-jsonl-v1","execution_successful":true}\n' >"$native"
			execute_planned "$index" staticcheck >>"$native"
			status=$?
			;;
		golangci-lint/default)
			execute_planned "$index" golangci-lint --config "$CENTRAL_DIR/configs/golangci.yml" --output.text.path /dev/null --output.json.path "$native"
			status=$?
			;;
		govulncheck/modules)
			execute_planned "$index" govulncheck >"$native"
			status=$?
			;;
		*)
			set -e
			return 2
			;;
		esac
		set -e
		[[ -s "$native" ]] || return 2
		((status == 0)) || overall=1
		aggregate_inputs+=("$module=$native")
	done
	local report="$reports/$name.native"
	aggregate_parts "$parser" "$report" "${aggregate_inputs[@]}"
	record_result "$tool" "$command_id" "$version" "$report" "$overall"
}

run_unrecorded_group() {
	local mode=$1 index
	for index in "${!modules[@]}"; do
		case "$mode" in
		compatibility)
			execute_planned "$index" build
			execute_planned "$index" test
			;;
		codeql-build)
			execute_planned "$index" build
			;;
		esac
	done
}

case "$group" in
formatting)
	run_format gofmt gofmt/tracked-go "$(go version)" gofmt
	run_format goimports goimports/tracked-go 0.49.0 goimports
	;;
core)
	run_module_command go go/module-integrity "$(go version)" command-status
	run_module_command go go/build "$(go version)" command-status
	run_module_command go go/vet "$(go version)" command-status
	run_module_command gopls gopls/tracked-go 0.23.0 gopls
	;;
tests)
	run_module_command go go/test "$(gotestsum --version)" junit
	run_module_command go go/race "$(gotestsum --version)" junit
	;;
analysis)
	run_module_command staticcheck staticcheck/default "$(staticcheck -version)" staticcheck
	run_module_command golangci-lint golangci-lint/default 2.12.2 golangci-lint
	run_module_command govulncheck govulncheck/modules 1.7.0 govulncheck
	;;
compatibility | codeql-build)
	run_unrecorded_group "$group"
	;;
*)
	printf 'unsupported Go group: %s\n' "$group" >&2
	exit 2
	;;
esac
