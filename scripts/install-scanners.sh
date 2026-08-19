#!/usr/bin/env bash
set -euo pipefail

: "${BIN_DIR:?}"

group=${1:?scanner group is required}
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
	printf 'scanner installation supports Linux x86_64 only\n' >&2
	exit 2
}

mkdir -p "$BIN_DIR"
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/github-ci-scanners.XXXXXX")
trap 'rm -rf "$work"' EXIT

download() {
	local name=$1 url=$2 digest=$3
	curl --fail --location --silent --show-error "$url" --output "$work/$name"
	printf '%s  %s\n' "${digest#sha256:}" "$work/$name" | sha256sum --check --status
}

install_release_asset() {
	local name=$1 url=$2 digest=$3 kind=$4 member=${5:-}
	download "$name.download" "$url" "$digest"
	case "$kind" in
	raw)
		install -m 0755 "$work/$name.download" "$BIN_DIR/$name"
		;;
	tar.gz)
		mkdir -p "$work/$name"
		tar -xzf "$work/$name.download" -C "$work/$name"
		install -m 0755 "$work/$name/$member" "$BIN_DIR/$name"
		;;
	tar.xz)
		mkdir -p "$work/$name"
		tar -xJf "$work/$name.download" -C "$work/$name"
		install -m 0755 "$work/$name/$member" "$BIN_DIR/$name"
		;;
	*)
		printf 'unsupported release asset kind: %s\n' "$kind" >&2
		exit 2
		;;
	esac
}

install_security() {
	install_release_asset gitleaks \
		https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
		sha256:551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb tar.gz gitleaks
	install_release_asset osv-scanner \
		https://github.com/google/osv-scanner/releases/download/v2.5.1/osv-scanner_linux_amd64 \
		sha256:f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be raw
	install_release_asset trivy \
		https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz \
		sha256:2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a tar.gz trivy
	"$BIN_DIR/gitleaks" version 2>&1 | grep -F '8.30.1'
	"$BIN_DIR/osv-scanner" --version 2>&1 | grep -F '2.5.1'
	"$BIN_DIR/trivy" version 2>&1 | grep -F 'Version: 0.74.0'
}

install_supply_chain() {
	install_release_asset syft \
		https://github.com/anchore/syft/releases/download/v1.51.0/syft_1.51.0_linux_amd64.tar.gz \
		sha256:2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f tar.gz syft
	install_release_asset grype \
		https://github.com/anchore/grype/releases/download/v0.117.0/grype_0.117.0_linux_amd64.tar.gz \
		sha256:38525dab1e06f162ebaa02f94d82d1f807076b011a44180cf2777edf1a7b9c26 tar.gz grype
	GOBIN="$BIN_DIR" go install github.com/google/go-licenses/v2@v2.0.1
	GOBIN="$BIN_DIR" go install golang.org/x/exp/cmd/apidiff@v0.0.0-20260813180055-c1d0aacb2297
	"$BIN_DIR/syft" version 2>&1 | grep -F '1.51.0'
	"$BIN_DIR/grype" version 2>&1 | grep -F '0.117.0'
	go version -m "$BIN_DIR/go-licenses" | grep -F $'mod\tgithub.com/google/go-licenses/v2\tv2.0.1'
	go version -m "$BIN_DIR/apidiff" | grep -F $'mod\tgolang.org/x/exp\tv0.0.0-20260813180055-c1d0aacb2297'
}

install_repository() {
	install_release_asset actionlint \
		https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz \
		sha256:8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 tar.gz actionlint
	install_release_asset hadolint \
		https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-linux-x86_64 \
		sha256:c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507 raw
	install_release_asset shellcheck \
		https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz \
		sha256:8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198 tar.xz shellcheck-v0.11.0/shellcheck
	install_release_asset shfmt \
		https://github.com/mvdan/sh/releases/download/v3.13.1/shfmt_v3.13.1_linux_amd64 \
		sha256:fb096c5d1ac6beabbdbaa2874d025badb03ee07929f0c9ff67563ce8c75398b1 raw

	download zizmor.whl \
		https://files.pythonhosted.org/packages/b4/f0/dfa67018b76bc4f2f50e265e8cbd1293833d1b1de5f3f02fbbb7487ae9c6/zizmor-1.29.0-py3-none-manylinux_2_28_x86_64.whl \
		sha256:587b99c2e1b34575c6c8565c2bfde415ca8bc0310f5589f19bc948c8dea10a20
	mkdir -p "$work/zizmor"
	unzip -q "$work/zizmor.whl" -d "$work/zizmor"
	install -m 0755 "$work/zizmor/zizmor-1.29.0.data/scripts/zizmor" "$BIN_DIR/zizmor"

	download yamllint-1.38.0-py3-none-any.whl \
		https://files.pythonhosted.org/packages/05/92/aed08e68de6e6a3d7c2328ce7388072cd6affc26e2917197430b646aed02/yamllint-1.38.0-py3-none-any.whl \
		sha256:fc394a5b3be980a4062607b8fdddc0843f4fa394152b6da21722f5d59013c220
	download pathspec-1.1.1-py3-none-any.whl \
		https://files.pythonhosted.org/packages/f1/d9/7fb5aa316bc299258e68c73ba3bddbc499654a07f151cba08f6153988714/pathspec-1.1.1-py3-none-any.whl \
		sha256:a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189
	download pyyaml-6.0.3-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl \
		https://files.pythonhosted.org/packages/71/60/917329f640924b18ff085ab889a11c763e0b573da888e8404ff486657602/pyyaml-6.0.3-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl \
		sha256:b8bb0864c5a28024fac8a632c443c87c5aa6f215c0b126c449ae1a150412f31d
	python3 -m venv "$BIN_DIR/yamllint-venv"
	"$BIN_DIR/yamllint-venv/bin/pip" install --disable-pip-version-check --no-index \
		"$work/pathspec-1.1.1-py3-none-any.whl" \
		"$work/pyyaml-6.0.3-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl" \
		"$work/yamllint-1.38.0-py3-none-any.whl"
	ln -s "$BIN_DIR/yamllint-venv/bin/yamllint" "$BIN_DIR/yamllint"

	"$BIN_DIR/actionlint" -version 2>&1 | grep -F '1.7.12'
	"$BIN_DIR/hadolint" --version 2>&1 | grep -F '2.15.1'
	"$BIN_DIR/shellcheck" --version 2>&1 | grep -F 'version: 0.11.0'
	"$BIN_DIR/shfmt" --version 2>&1 | grep -F 'v3.13.1'
	"$BIN_DIR/zizmor" --version 2>&1 | grep -F '1.29.0'
	"$BIN_DIR/yamllint" --version 2>&1 | grep -F '1.38.0'
}

install_deep() {
	install_release_asset gitleaks \
		https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
		sha256:551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb tar.gz gitleaks
	GOBIN="$BIN_DIR" go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0
	"$BIN_DIR/gitleaks" version 2>&1 | grep -F '8.30.1'
	go version -m "$BIN_DIR/gremlins" | grep -F $'mod\tgithub.com/go-gremlins/gremlins\tv0.6.0'
}

case "$group" in
security) install_security ;;
supply-chain) install_supply_chain ;;
repository) install_repository ;;
deep) install_deep ;;
*)
	printf 'unsupported scanner group: %s\n' "$group" >&2
	exit 2
	;;
esac
