#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bazel_binary="${BAZEL:-$(command -v bazel || true)}"
if [[ -z "${bazel_binary}" ]]; then
  bazel_binary="$(command -v bazelisk || true)"
fi
if [[ -z "${bazel_binary}" ]]; then
  echo "bazel or bazelisk must be on PATH, or set BAZEL to its executable path" >&2
  exit 1
fi

build_options=()
if [[ "$(uname -s)" == "Darwin" ]]; then
  build_options+=(--macos_minimum_os=10.15)
fi

cd "${repository_root}"
"${bazel_binary}" build "${build_options[@]}" //:envoy-modsecurity
exec python3 "${repository_root}/tools/owasp-crs-lab.py" \
  --envoy-binary "${repository_root}/bazel-bin/envoy-modsecurity" \
  "$@"
