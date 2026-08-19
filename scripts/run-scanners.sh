#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_CI_CLI:?}"
: "${SOURCE_DIR:?}"
: "${CENTRAL_DIR:?}"
: "${PLAN_PATH:?}"
: "${CONFIG_PATH:?}"
: "${OUTPUT_DIR:?}"
: "${BIN_DIR:?}"

export PATH="$BIN_DIR:$PATH"
group=${1:?scanner group is required}
records="$OUTPUT_DIR/records"
reports="$OUTPUT_DIR/reports"
parts="$OUTPUT_DIR/parts"
docker_source_dir=${DOCKER_SOURCE_DIR:-$SOURCE_DIR}
docker_central_dir=${DOCKER_CENTRAL_DIR:-$CENTRAL_DIR}
docker_reports_dir=${DOCKER_REPORTS_DIR:-$reports}
mkdir -p "$records" "$reports" "$parts"

safe_name() {
	printf '%s' "${1//\//--}"
}

report_path() {
	printf '%s/%s.native' "$reports" "$(safe_name "$1--$2")"
}

record_result() {
	local tool=$1 command_id=$2 version=$3 report=${4:-} exit_code=${5:-0}
	local record status
	record="$records/$(safe_name "$tool--$command_id").json"
	set +e
	if [[ -n "$report" ]]; then
		"$GITHUB_CI_CLI" record --plan "$PLAN_PATH" --tool "$tool" --command-id "$command_id" \
			--tool-version "$version" --report "$report" --exit-code "$exit_code" --output "$record"
	else
		"$GITHUB_CI_CLI" record --plan "$PLAN_PATH" --tool "$tool" --command-id "$command_id" \
			--tool-version "$version" --output "$record"
	fi
	status=$?
	set -e
	((status <= 1)) || return "$status"
}

is_applicable() {
	local tool=$1 command_id=$2 version=$3 status
	set +e
	"$GITHUB_CI_CLI" applicable --plan "$PLAN_PATH" --tool "$tool" --command-id "$command_id"
	status=$?
	set -e
	if ((status == 1)); then
		record_result "$tool" "$command_id" "$version"
		return 1
	fi
	((status == 0)) || return "$status"
}

plan_expects() {
	local tool=$1 command_id=$2 status
	set +e
	jq -e --arg tool "$tool" --arg command "$command_id" \
		'any(.expected[]; .tool == $tool and .command_id == $command)' "$PLAN_PATH" >/dev/null
	status=$?
	set -e
	if ((status == 1)); then
		return 1
	fi
	((status == 0)) || return "$status"
}

begin_tool() {
	local status expected_status
	set +e
	plan_expects "$1" "$2"
	expected_status=$?
	set -e
	if ((expected_status == 1)); then
		return 1
	fi
	if ((expected_status != 0)); then
		printf 'plan lookup failed for %s/%s\n' "$1" "$2" >&2
		exit "$expected_status"
	fi
	set +e
	is_applicable "$1" "$2" "$3"
	status=$?
	set -e
	if ((status == 1)); then
		return 1
	fi
	if ((status != 0)); then
		printf 'applicability check failed for %s/%s\n' "$1" "$2" >&2
		exit "$status"
	fi
}

write_path_list() {
	local output=$1
	shift
	printf '%s\n' "$@" | sed '/^$/d' | LC_ALL=C sort -u | jq -Rn '[inputs] | {schema_version:"1",paths:.}' >"$output"
}

write_status() {
	local output=$1 status=$2
	jq -cn --argjson successful "$([[ $status -eq 0 ]] && printf true || printf false)" \
		'{schema_version:"1",execution_successful:$successful}' >"$output"
}

tracked_files() {
	"$GITHUB_CI_CLI" files --repository "$SOURCE_DIR" --config "$CONFIG_PATH" --kind "$1"
}

run_gitleaks() {
	begin_tool gitleaks gitleaks/content 8.30.1 || return 0
	local report status
	report=$(report_path gitleaks gitleaks/content)
	set +e
	gitleaks dir --no-banner --redact=100 --report-format json --report-path "$report" "$SOURCE_DIR"
	status=$?
	set -e
	((status <= 1)) || return "$status"
	[[ -s "$report" ]] || printf '[]\n' >"$report"
	record_result gitleaks gitleaks/content 8.30.1 "$report" "$status"
}

run_osv() {
	begin_tool osv-scanner osv-scanner/dependencies 2.5.1 || return 0
	local report status
	report=$(report_path osv-scanner osv-scanner/dependencies)
	set +e
	osv-scanner scan source --recursive --no-ignore --format json --output-file "$report" "$SOURCE_DIR"
	status=$?
	set -e
	((status <= 1)) || return "$status"
	[[ -s "$report" ]] || return 2
	record_result osv-scanner osv-scanner/dependencies 2.5.1 "$report" "$status"
}

run_trivy() {
	begin_tool trivy trivy/filesystem 0.74.0 || return 0
	local report status
	report=$(report_path trivy trivy/filesystem)
	set +e
	trivy fs --cache-dir "${RUNNER_TEMP:-/tmp}/github-ci-trivy" --format json --output "$report" --exit-code 1 --scanners vuln,misconfig,secret \
		--skip-version-check --disable-telemetry \
		--no-progress "$SOURCE_DIR"
	status=$?
	set -e
	((status <= 1)) || return "$status"
	[[ -s "$report" ]] || return 2
	record_result trivy trivy/filesystem 0.74.0 "$report" "$status"
}

run_semgrep() {
	begin_tool semgrep semgrep/source 1.173.0 || return 0
	: "${SEMGREP_IMAGE:?}"
	local report status
	report=$(report_path semgrep semgrep/source)
	set +e
	docker run --rm --user "$(id -u):$(id -g)" --network none --cap-drop ALL --security-opt no-new-privileges \
		--tmpfs /tmp:rw,noexec,nosuid,size=64m \
		-e HOME=/tmp -e SEMGREP_SETTINGS_FILE=/tmp/semgrep-settings.yml \
		--read-only -v "$docker_source_dir:/src:ro" -v "$docker_central_dir/policies:/policy:ro" \
		-v "$docker_reports_dir:/out" --entrypoint semgrep "$SEMGREP_IMAGE" \
		scan --metrics off --error --config /policy/semgrep.yaml --json --output "/out/$(basename "$report")" /src
	status=$?
	set -e
	((status <= 1)) || return "$status"
	[[ -s "$report" ]] || return 2
	record_result semgrep semgrep/source 1.173.0 "$report" "$status"
}

run_syft() {
	begin_tool syft syft/sbom 1.51.0 || return 0
	local report syft_json status
	report=$(report_path syft syft/sbom)
	syft_json="$parts/syft.json"
	set +e
	syft "dir:$SOURCE_DIR" --quiet --output "spdx-json=$report" --output "syft-json=$syft_json"
	status=$?
	set -e
	((status == 0)) || return "$status"
	[[ -s "$report" && -s "$syft_json" ]] || return 2
	record_result syft syft/sbom 1.51.0 "$report" 0
}

run_grype() {
	begin_tool grype grype/sbom 0.117.0 || return 0
	local report syft_json status
	report=$(report_path grype grype/sbom)
	syft_json="$parts/syft.json"
	[[ -s "$syft_json" ]] || return 2
	set +e
	grype "sbom:$syft_json" --quiet --output json --file "$report" --fail-on negligible
	status=$?
	set -e
	((status == 0 || status == 2)) || return "$status"
	[[ -s "$report" ]] || return 2
	record_result grype grype/sbom 0.117.0 "$report" "$([[ $status -eq 0 ]] && printf 0 || printf 1)"
}

run_licenses() {
	begin_tool license license/dependencies 2.0.1 || return 0
	local report csv status module module_dir module_path index=0
	local -a modules csv_files
	report=$(report_path license license/dependencies)
	while IFS= read -r module; do modules+=("$module"); done < <(
		"$GITHUB_CI_CLI" modules --repository "$SOURCE_DIR" --config "$CONFIG_PATH" | jq -r '.modules[]'
	)
	for module in "${modules[@]}"; do
		module_dir="$SOURCE_DIR"
		[[ "$module" == . ]] || module_dir="$SOURCE_DIR/$module"
		csv="$parts/licenses-$index.csv"
		set +e
		(cd "$module_dir" && go-licenses report ./...) >"$csv"
		status=$?
		set -e
		((status == 0)) || return "$status"
		module_path=$(sed -n 's/^module[[:space:]]\+//p' "$module_dir/go.mod" | head -1)
		[[ -n "$module_path" ]] || return 2
		csv_files+=("$module_path=$csv")
		((index += 1))
	done
	python3 - "$CENTRAL_DIR/policies/licenses.yaml" "$report" "${csv_files[@]}" <<'PY'
import csv
import json
import sys

policy_path, output_path, *inputs = sys.argv[1:]
with open(policy_path, encoding="utf-8") as stream:
    allowed = set(json.load(stream)["allowed"])
dependencies = {}
for entry in inputs:
    module, name = entry.split("=", 1)
    with open(name, newline="", encoding="utf-8") as stream:
        for row in csv.reader(stream):
            if len(row) != 3 or not row[0] or not row[2]:
                raise SystemExit("invalid go-licenses report row")
            if row[0] == module or row[0].startswith(module + "/"):
                continue
            dependencies[row[0]] = row[2]
items = [{"package": package, "license": license_id} for package, license_id in sorted(dependencies.items())]
violations = [
    {"package": item["package"], "license": item["license"], "reason": "license is not allowed"}
    for item in items if item["license"] not in allowed
]
with open(output_path, "w", encoding="utf-8") as stream:
    json.dump({"schema_version": "1", "dependencies": items, "violations": violations}, stream, separators=(",", ":"))
    stream.write("\n")
PY
	record_result license license/dependencies 2.0.1 "$report" 0
}

latest_stable_tag() {
	git -C "$SOURCE_DIR" tag --merged HEAD --sort=-version:refname | grep -E '(^|/)v[0-9]+\.[0-9]+\.[0-9]+$' | head -1
}

run_apidiff() {
	begin_tool apidiff apidiff/public-api 0.0.0-20260813180055-c1d0aacb2297 || return 0
	local report tag old_dir status module module_dir index=0
	local -a modules findings
	report=$(report_path apidiff apidiff/public-api)
	tag=$(latest_stable_tag || true)
	if [[ -z "$tag" ]]; then
		write_path_list "$report"
		record_result apidiff apidiff/public-api 0.0.0-20260813180055-c1d0aacb2297 "$report" 0
		return
	fi
	old_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/github-ci-apidiff.XXXXXX")
	git -C "$SOURCE_DIR" archive "$tag" | tar -xf - -C "$old_dir"
	while IFS= read -r module; do modules+=("$module"); done < <(
		"$GITHUB_CI_CLI" modules --repository "$SOURCE_DIR" --config "$CONFIG_PATH" | jq -r '.modules[]'
	)
	for module in "${modules[@]}"; do
		module_dir="$SOURCE_DIR"
		[[ "$module" == . ]] || module_dir="$SOURCE_DIR/$module"
		[[ -f "$old_dir/${module#./}/go.mod" || "$module" == . && -f "$old_dir/go.mod" ]] || continue
		local old_module_dir="$old_dir"
		[[ "$module" == . ]] || old_module_dir="$old_dir/$module"
		local module_path
		module_path=$(sed -n 's/^module[[:space:]]\+//p' "$module_dir/go.mod" | head -1)
		(cd "$old_module_dir" && apidiff -m -w "$parts/apidiff-old-$index.api" "$module_path")
		(cd "$module_dir" && apidiff -m -w "$parts/apidiff-new-$index.api" "$module_path")
		set +e
		apidiff -m -incompatible "$parts/apidiff-old-$index.api" "$parts/apidiff-new-$index.api" >"$parts/apidiff-$index.txt"
		status=$?
		set -e
		((status == 0)) || return "$status"
		[[ ! -s "$parts/apidiff-$index.txt" ]] || findings+=("${module#./}")
		((index += 1))
	done
	write_path_list "$report" "${findings[@]}"
	rm -rf "$old_dir"
	record_result apidiff apidiff/public-api 0.0.0-20260813180055-c1d0aacb2297 "$report" 0
}

run_actionlint() {
	begin_tool actionlint actionlint/workflows 1.7.12 || return 0
	local report raw status
	report=$(report_path actionlint actionlint/workflows)
	raw="$parts/actionlint.jsonl"
	set +e
	(cd "$SOURCE_DIR" && actionlint -format '{{json .}}') >"$raw"
	status=$?
	set -e
	((status <= 1)) || return "$status"
	jq -s 'if length == 1 and (.[0] | type) == "array" then .[0] else . end' "$raw" >"$report"
	record_result actionlint actionlint/workflows 1.7.12 "$report" "$status"
}

run_zizmor() {
	begin_tool zizmor zizmor/workflows 1.29.0 || return 0
	local report status
	report=$(report_path zizmor zizmor/workflows)
	set +e
	(cd "$SOURCE_DIR" && zizmor --format sarif --pedantic .github/workflows) >"$report"
	status=$?
	set -e
	((status <= 1)) || return "$status"
	[[ -s "$report" ]] || return 2
	record_result zizmor zizmor/workflows 1.29.0 "$report" "$status"
}

run_hadolint() {
	begin_tool hadolint hadolint/dockerfiles 2.15.1 || return 0
	local report status
	local -a files
	report=$(report_path hadolint hadolint/dockerfiles)
	while IFS= read -r -d '' file; do files+=("$file"); done < <(tracked_files docker)
	set +e
	(cd "$SOURCE_DIR" && hadolint --format sarif "${files[@]}") >"$report"
	status=$?
	set -e
	((status <= 1)) || return "$status"
	[[ -s "$report" ]] || return 2
	record_result hadolint hadolint/dockerfiles 2.15.1 "$report" "$status"
}

run_bash() {
	begin_tool bash bash/scripts "$(bash --version | head -1)" || return 0
	local report status file
	local -a files findings
	report=$(report_path bash bash/scripts)
	while IFS= read -r -d '' file; do files+=("$file"); done < <(tracked_files shell)
	for file in "${files[@]}"; do
		set +e
		bash -n "$SOURCE_DIR/$file"
		status=$?
		set -e
		((status == 0)) || findings+=("$file")
	done
	write_path_list "$report" "${findings[@]}"
	record_result bash bash/scripts "$(bash --version | head -1)" "$report" 0
}

run_shellcheck() {
	begin_tool shellcheck shellcheck/scripts 0.11.0 || return 0
	local report status
	local -a files
	report=$(report_path shellcheck shellcheck/scripts)
	while IFS= read -r -d '' file; do files+=("$file"); done < <(tracked_files shell)
	set +e
	(cd "$SOURCE_DIR" && shellcheck --format=json "${files[@]}") >"$report"
	status=$?
	set -e
	((status <= 1)) || return "$status"
	[[ -s "$report" ]] || printf '[]\n' >"$report"
	record_result shellcheck shellcheck/scripts 0.11.0 "$report" "$status"
}

run_shfmt() {
	begin_tool shfmt shfmt/scripts 3.13.1 || return 0
	local report file
	local -a files findings
	report=$(report_path shfmt shfmt/scripts)
	while IFS= read -r -d '' file; do files+=("$file"); done < <(tracked_files shell)
	for file in "${files[@]}"; do
		if [[ -n $(shfmt -d "$SOURCE_DIR/$file") ]]; then findings+=("$file"); fi
	done
	write_path_list "$report" "${findings[@]}"
	record_result shfmt shfmt/scripts 3.13.1 "$report" 0
}

run_yamllint() {
	begin_tool yamllint yamllint/documents 1.38.0 || return 0
	local report raw status
	local -a files
	report=$(report_path yamllint yamllint/documents)
	raw="$parts/yamllint.txt"
	while IFS= read -r -d '' file; do files+=("$file"); done < <(tracked_files yaml)
	set +e
	(cd "$SOURCE_DIR" && yamllint --config-file "$CENTRAL_DIR/policies/yamllint.yaml" --format parsable "${files[@]}") >"$raw"
	status=$?
	set -e
	((status <= 1)) || return "$status"
	printf '{"schema_version":"1","execution_successful":true}\n' >"$report"
	cat "$raw" >>"$report"
	record_result yamllint yamllint/documents 1.38.0 "$report" "$status"
}

run_markdownlint() {
	begin_tool markdownlint markdownlint/documents 0.23.2 || return 0
	: "${MARKDOWNLINT_IMAGE:?}"
	local report status file
	local -a files findings
	report=$(report_path markdownlint markdownlint/documents)
	while IFS= read -r -d '' file; do files+=("$file"); done < <(tracked_files markdown)
	for file in "${files[@]}"; do
		set +e
		docker run --rm --user "$(id -u):$(id -g)" --network none --cap-drop ALL --security-opt no-new-privileges --read-only \
			--tmpfs /tmp:rw,noexec,nosuid,size=64m \
			-v "$docker_source_dir:/workdir:ro" "$MARKDOWNLINT_IMAGE" "$file"
		status=$?
		set -e
		((status <= 1)) || return "$status"
		((status == 0)) || findings+=("$file")
	done
	write_path_list "$report" "${findings[@]}"
	record_result markdownlint markdownlint/documents 0.23.2 "$report" 0
}

run_json() {
	begin_tool json json/documents "$(jq --version)" || return 0
	local report file
	local -a files findings
	report=$(report_path json json/documents)
	while IFS= read -r -d '' file; do files+=("$file"); done < <(tracked_files json)
	for file in "${files[@]}"; do jq empty "$SOURCE_DIR/$file" >/dev/null 2>&1 || findings+=("$file"); done
	write_path_list "$report" "${findings[@]}"
	record_result json json/documents "$(jq --version)" "$report" 0
}

run_checkov() {
	begin_tool checkov checkov/infrastructure 3.3.11 || return 0
	: "${CHECKOV_IMAGE:?}"
	local report output_directory status
	report=$(report_path checkov checkov/infrastructure)
	output_directory="$reports/checkov-output"
	mkdir -p "$output_directory"
	set +e
	docker run --rm --user "$(id -u):$(id -g)" --network none --cap-drop ALL --security-opt no-new-privileges --read-only \
		--tmpfs /tmp:rw,noexec,nosuid,size=64m \
		-v "$docker_source_dir:/src:ro" -v "$docker_reports_dir:/out" --entrypoint checkov "$CHECKOV_IMAGE" \
		-d /src --framework terraform --output json --output-file-path /out/checkov-output --quiet --skip-download
	status=$?
	set -e
	((status <= 1)) || return "$status"
	[[ -s "$output_directory/results_json.json" ]] || return 2
	mv "$output_directory/results_json.json" "$report"
	rmdir "$output_directory"
	[[ -s "$report" ]] || return 2
	record_result checkov checkov/infrastructure 3.3.11 "$report" "$status"
}

run_hygiene() {
	begin_tool repository repository/hygiene 1 || return 0
	local report path mode
	local -a findings
	report=$(report_path repository repository/hygiene)
	while IFS= read -r -d '' path; do
		case "$path" in
		.DS_Store | */.DS_Store | *.swp | *.swo | *~ | *.orig | *.rej | *.pem | *.key | *.p12 | *.pfx) findings+=("$path") ;;
		esac
		if [[ -L "$SOURCE_DIR/$path" && ! -e "$SOURCE_DIR/$path" ]]; then findings+=("$path"); fi
		mode=$(git -C "$SOURCE_DIR" ls-files -s -- "$path" | awk '{print $1}')
		[[ "$mode" != 160000 ]] || findings+=("$path")
	done < <(git -C "$SOURCE_DIR" ls-files -z)
	write_path_list "$report" "${findings[@]}"
	record_result repository repository/hygiene 1 "$report" 0
}

run_generated() {
	begin_tool generated generated/files 1 || return 0
	local report status=0
	report=$(report_path generated generated/files)
	if [[ -f "$SOURCE_DIR/go.mod" ]] && grep -qx 'module github.com/gomaja/github-ci' "$SOURCE_DIR/go.mod"; then
		set +e
		"$GITHUB_CI_CLI" verify-generated --root "$SOURCE_DIR"
		status=$?
		set -e
	fi
	if ((status == 0)); then write_path_list "$report"; else write_path_list "$report" templates; fi
	record_result generated generated/files 1 "$report" "$([[ $status -eq 0 ]] && printf 0 || printf 1)"
}

case "$group" in
security)
	run_gitleaks
	run_osv
	run_trivy
	run_semgrep
	;;
supply-chain)
	run_syft
	run_grype
	run_licenses
	run_apidiff
	;;
repository)
	run_actionlint
	run_zizmor
	run_hadolint
	run_bash
	run_shellcheck
	run_shfmt
	run_yamllint
	run_markdownlint
	run_json
	run_checkov
	run_hygiene
	run_generated
	;;
*)
	printf 'unsupported scanner group: %s\n' "$group" >&2
	exit 2
	;;
esac
