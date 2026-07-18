#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_ftw_version="2.4.0"
albedo_version="0.3.0"

case "$(uname -s)" in
  Darwin)
    artifact_os="darwin"
    report_os="darwin"
    ;;
  Linux)
    artifact_os="linux"
    report_os="linux"
    ;;
  *)
    echo "Unsupported operating system: $(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  arm64 | aarch64)
    artifact_arch="arm64"
    ;;
  x86_64 | amd64)
    artifact_arch="amd64"
    ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

case "${artifact_os}-${artifact_arch}" in
  darwin-arm64)
    go_ftw_sha256="36477c7d72ae1bd5d38e145bb7fcad592823d6c3c555467255ae507665b83b20"
    albedo_sha256="c0131200452918581055dfa3a0d220103d8db6170f6586f52e233a01cd4526d8"
    ;;
  darwin-amd64)
    go_ftw_sha256="c8f2238d60c4584d79ca2be119250ac3d3f703b247d67926e347780b3e0bb467"
    albedo_sha256="20849c7514ab67c65ef9198444ec84a6cb2eb52eafa9d8b18538ae5dd3189432"
    ;;
  linux-arm64)
    go_ftw_sha256="09972291e51f19564f92f3a92c468424a4bb69694ac57049b4a0574aceb1912a"
    albedo_sha256="c74f63f28f3e763b888f433c78888e4a928796d07d44e4edf3d53c8d07302e44"
    ;;
  linux-amd64)
    go_ftw_sha256="6e39cb3817f1e042c6385d0df63b1fe7170788524d3e18ecd9c82282969bcf78"
    albedo_sha256="7b6408cd64935662a4d6ff8755d43ca06b57b39ff4f260e7c45c90acc33ba0b5"
    ;;
esac

tools_directory="${CRS_TEST_TOOLS_DIR:-${TMPDIR:-/tmp}/envoy-modsecurity-crs-tools}"
mkdir -p "${tools_directory}"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}

fetch_tool() {
  local project="$1"
  local version="$2"
  local archive_prefix="$3"
  local binary_name="$4"
  local expected_sha256="$5"
  local destination="${tools_directory}/${project}-${version}-${artifact_os}-${artifact_arch}"
  local archive_name="${archive_prefix}_${version}_${artifact_os}_${artifact_arch}.tar.gz"
  local archive_path="${tools_directory}/${archive_name}"
  local binary_path="${destination}/${binary_name}"

  if [[ ! -x "${binary_path}" ]]; then
    mkdir -p "${destination}"
    curl --fail --location \
      --output "${archive_path}" \
      "https://github.com/coreruleset/${project}/releases/download/v${version}/${archive_name}"
    local actual_sha256
    actual_sha256="$(sha256_file "${archive_path}")"
    if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
      echo "Checksum mismatch for ${archive_name}: ${actual_sha256}" >&2
      exit 1
    fi
    tar -xzf "${archive_path}" -C "${destination}"
  fi

  printf '%s\n' "${binary_path}"
}

go_ftw_binary="${CRS_GO_FTW_BINARY:-}"
if [[ -z "${go_ftw_binary}" ]]; then
  go_ftw_binary="$(fetch_tool go-ftw "${go_ftw_version}" ftw ftw "${go_ftw_sha256}")"
fi

albedo_binary="${CRS_ALBEDO_BINARY:-}"
if [[ -z "${albedo_binary}" ]]; then
  albedo_binary="$(fetch_tool albedo "${albedo_version}" albedo albedo "${albedo_sha256}")"
fi

envoy_binary="${repository_root}/bazel-bin/envoy-modsecurity"
if [[ ! -x "${envoy_binary}" ]]; then
  bazel_binary="$(command -v bazel || true)"
  if [[ -z "${bazel_binary}" ]]; then
    bazel_binary="/Users/seonghyun/Library/Caches/bazelisk/downloads/sha256/575f20fb23955e02f73519befd180df635b4ed0960c60f0e70fcc8d74014a713/bin/bazel"
  fi
  if [[ "${artifact_os}" == "darwin" ]]; then
    "${bazel_binary}" build --macos_minimum_os=10.15 //:envoy-modsecurity
  else
    "${bazel_binary}" build //:envoy-modsecurity
  fi
fi

output_directory="${CRS_REPORT_OUTPUT_DIR:-${repository_root}/artifacts/crs-compatibility-${report_os}-${artifact_arch}}"
exec python3 "${repository_root}/tools/crs-compatibility-report.py" \
  --envoy-binary "${envoy_binary}" \
  --go-ftw-binary "${go_ftw_binary}" \
  --albedo-binary "${albedo_binary}" \
  --output-directory "${output_directory}" \
  "$@"
