#!/usr/bin/env bash

load_go_modules() {
	local plan_path=${1:?Go execution plan path is required}
	jq -e '
    .schema_version == "1" and
    (.modules | type == "array") and
    all(.modules[];
      (.path | type == "string") and
      (.directory | type == "string") and
      (.invocations | type == "object")
    )
  ' "$plan_path" >/dev/null
	GO_PLAN_MODULE_PATHS=()
	GO_PLAN_MODULE_DIRECTORIES=()
	while IFS= read -r -d '' value; do
		GO_PLAN_MODULE_PATHS+=("$value")
	done < <(jq -j '.modules[] | .path, "\u0000"' "$plan_path")
	while IFS= read -r -d '' value; do
		GO_PLAN_MODULE_DIRECTORIES+=("$value")
	done < <(jq -j '.modules[] | .directory, "\u0000"' "$plan_path")
	((${#GO_PLAN_MODULE_PATHS[@]} > 0))
	((${#GO_PLAN_MODULE_PATHS[@]} == ${#GO_PLAN_MODULE_DIRECTORIES[@]}))
}

load_go_invocation() {
	local plan_path=${1:?Go execution plan path is required}
	local module_index=${2:?module index is required}
	local tool=${3:?tool is required}
	[[ "$module_index" =~ ^[0-9]+$ ]]
	case "$tool" in
	build | test | race | vet | gopls | staticcheck | golangci-lint | govulncheck) ;;
	*) return 2 ;;
	esac
	jq -e --argjson module_index "$module_index" --arg tool "$tool" '
    .schema_version == "1" and
    (.modules[$module_index] | type == "object") and
    (.modules[$module_index].invocations[$tool].environment | type == "array") and
    all(.modules[$module_index].invocations[$tool].environment[]; type == "string") and
    (.modules[$module_index].invocations[$tool].arguments | type == "array" and length > 0) and
    all(.modules[$module_index].invocations[$tool].arguments[]; type == "string")
  ' "$plan_path" >/dev/null

	GO_PLAN_ENVIRONMENT=()
	GO_PLAN_ARGUMENTS=()
	while IFS= read -r -d '' value; do
		[[ "$value" == GOFLAGS=* || "$value" == GOMAXPROCS=* ]]
		GO_PLAN_ENVIRONMENT+=("$value")
	done < <(jq -j --argjson module_index "$module_index" --arg tool "$tool" '.modules[$module_index].invocations[$tool].environment[] | ., "\u0000"' "$plan_path")
	while IFS= read -r -d '' value; do
		GO_PLAN_ARGUMENTS+=("$value")
	done < <(jq -j --argjson module_index "$module_index" --arg tool "$tool" '.modules[$module_index].invocations[$tool].arguments[] | ., "\u0000"' "$plan_path")

	local expected_executable=$tool
	case "$tool" in
	build | test | race | vet) expected_executable=go ;;
	esac
	[[ "${GO_PLAN_ARGUMENTS[0]}" == "$expected_executable" ]]
}
