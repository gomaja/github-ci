#!/usr/bin/env bash
set -euo pipefail

: "${CENTRAL_DIR:?}"
: "${SOURCE_DIR:?}"
: "${GO_PLAN_PATH:?}"

if [[ -n ${RUNNER_TEMP:-} ]]; then
	export PATH="$RUNNER_TEMP/github-ci-bin:$PATH"
fi

mode=${1:?deep execution mode is required}
source "$CENTRAL_DIR/scripts/load-go-plan.sh"
load_go_modules "$GO_PLAN_PATH"

module_directory() {
	local index=$1
	if [[ "${GO_PLAN_MODULE_DIRECTORIES[$index]}" == "." ]]; then
		printf '%s' "$SOURCE_DIR"
	else
		printf '%s' "$SOURCE_DIR/${GO_PLAN_MODULE_DIRECTORIES[$index]}"
	fi
}

execute_with_plan_environment() {
	local directory=$1
	shift
	if ((${#GO_PLAN_ENVIRONMENT[@]} == 0)); then
		(cd "$directory" && "$@")
	else
		(cd "$directory" && env "${GO_PLAN_ENVIRONMENT[@]}" "$@")
	fi
}

execute_planned() {
	local index=$1 tool=$2 directory
	load_go_invocation "$GO_PLAN_PATH" "$index" "$tool"
	directory=$(module_directory "$index")
	execute_with_plan_environment "$directory" "${GO_PLAN_ARGUMENTS[@]}"
}

load_module_packages() {
	local index=$1
	GO_PLAN_PACKAGES=()
	while IFS= read -r -d '' package; do
		GO_PLAN_PACKAGES+=("$package")
	done < <(jq -j --argjson module_index "$index" '
    .modules[$module_index].packages[] | ., "\u0000"
  ' "$GO_PLAN_PATH")
	((${#GO_PLAN_PACKAGES[@]} > 0))
}

run_portability() {
	local index
	for index in "${!GO_PLAN_MODULE_PATHS[@]}"; do
		execute_planned "$index" build
		execute_planned "$index" test
		execute_planned "$index" vet
	done
}

run_fuzz_benchmark() {
	: "${FUZZ_TIME:?}"
	[[ "$FUZZ_TIME" =~ ^[1-9][0-9]*(s|m)$ ]]

	local index directory argument package target base_count list_output target_output
	local -a list_arguments test_base concrete_packages targets
	for index in "${!GO_PLAN_MODULE_PATHS[@]}"; do
		directory=$(module_directory "$index")
		load_module_packages "$index"

		load_go_invocation "$GO_PLAN_PATH" "$index" build
		list_arguments=(go list)
		for argument in "${GO_PLAN_ARGUMENTS[@]:2}"; do
			list_arguments+=("$argument")
		done
		if ! list_output=$(execute_with_plan_environment "$directory" "${list_arguments[@]}"); then
			return 1
		fi
		concrete_packages=()
		while IFS= read -r package; do
			[[ -z "$package" ]] || concrete_packages+=("$package")
		done <<<"$list_output"
		((${#concrete_packages[@]} > 0))

		load_go_invocation "$GO_PLAN_PATH" "$index" test
		base_count=$((${#GO_PLAN_ARGUMENTS[@]} - ${#GO_PLAN_PACKAGES[@]}))
		((base_count >= 2))
		test_base=()
		for ((argument = 0; argument < base_count; argument++)); do
			test_base+=("${GO_PLAN_ARGUMENTS[$argument]}")
		done

		for package in "${concrete_packages[@]}"; do
			if ! target_output=$(execute_with_plan_environment "$directory" "${test_base[@]}" "$package" -list='^Fuzz'); then
				return 1
			fi
			targets=()
			while IFS= read -r target; do
				[[ "$target" =~ ^Fuzz[[:alnum:]_]*$ ]] && targets+=("$target")
			done <<<"$target_output"
			for target in "${targets[@]}"; do
				execute_with_plan_environment "$directory" "${test_base[@]}" "$package" -run='^$' -fuzz="^${target}$" -fuzztime="$FUZZ_TIME"
			done
		done

		execute_with_plan_environment "$directory" "${test_base[@]}" "${GO_PLAN_PACKAGES[@]}" -run='^$' -bench=. -benchtime=1s
	done
}

run_mutation_context() {
	: "${GITHUB_CI_CLI:?}"
	: "${MUTATION_DIR:?}"
	mkdir -p "$MUTATION_DIR"

	local index directory module_path report transcript evidence package package_index argument list_output relative_package
	local -a list_arguments concrete_packages mutation_scope_arguments
	for index in "${!GO_PLAN_MODULE_PATHS[@]}"; do
		directory=$(module_directory "$index")
		load_module_packages "$index"
		load_go_invocation "$GO_PLAN_PATH" "$index" build
		module_path=$(execute_with_plan_environment "$directory" env GOWORK=off go list -m -f '{{.Path}}')
		list_arguments=(go list '-f={{.ImportPath}}')
		for argument in "${GO_PLAN_ARGUMENTS[@]:2}"; do
			list_arguments+=("$argument")
		done
		if ! list_output=$(execute_with_plan_environment "$directory" "${list_arguments[@]}"); then
			return 1
		fi
		concrete_packages=()
		while IFS= read -r package; do
			[[ -z "$package" ]] && continue
			if [[ "$package" == "$module_path" ]]; then
				relative_package=.
			elif [[ "$package" == "$module_path/"* ]]; then
				relative_package="./${package#"$module_path/"}"
			else
				printf 'package %q is outside module %q\n' "$package" "$module_path" >&2
				return 1
			fi
			concrete_packages+=("$relative_package")
		done <<<"$list_output"
		((${#concrete_packages[@]} > 0))
		load_go_invocation "$GO_PLAN_PATH" "$index" gopls

		for package_index in "${!concrete_packages[@]}"; do
			package=${concrete_packages[$package_index]}
			mutation_scope_arguments=()
			if [[ "$package" == . ]]; then
				mutation_scope_arguments=(--exclude-files '[/\\]')
			fi
			report="$MUTATION_DIR/module-${index}-package-${package_index}.json"
			transcript="$MUTATION_DIR/module-${index}-package-${package_index}.log"
			evidence="$MUTATION_DIR/module-${index}-package-${package_index}-no-results.json"
			execute_with_plan_environment "$directory" gremlins unleash \
				--workers 4 \
				--test-cpu 1 \
				--timeout-coefficient 100 \
				--output-statuses lctvs \
				--arithmetic-base \
				--conditionals-boundary \
				--conditionals-negation \
				--increment-decrement \
				--invert-assignments \
				--invert-bitwise \
				--invert-bwassign \
				--invert-logical \
				--invert-loopctrl \
				--invert-negatives \
				--remove-self-assignments \
				${mutation_scope_arguments[@]+"${mutation_scope_arguments[@]}"} \
				--output "$report" "$package" 2>&1 | tee "$transcript"
			if [[ -f "$report" ]]; then
				"$GITHUB_CI_CLI" validate-gremlins --report "$report" --module "$module_path"
			else
				"$GITHUB_CI_CLI" validate-gremlins-no-results --log "$transcript" --module "$module_path" --output "$evidence"
			fi
		done
	done
}

case "$mode" in
portability)
	run_portability
	;;
fuzz-benchmark)
	run_fuzz_benchmark
	;;
mutation-context)
	run_mutation_context
	;;
*)
	printf 'unsupported deep Go mode: %s\n' "$mode" >&2
	exit 2
	;;
esac
