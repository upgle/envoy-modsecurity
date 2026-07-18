#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
envoy_binary="${repository_root}/bazel-bin/envoy-modsecurity"

if [[ ! -x "${envoy_binary}" ]]; then
  bazel_binary="${BAZEL:-$(command -v bazel || true)}"
  if [[ -z "${bazel_binary}" ]]; then
    bazel_binary="$(command -v bazelisk || true)"
  fi
  if [[ -z "${bazel_binary}" ]]; then
    echo "bazel or bazelisk must be on PATH, or set BAZEL to its executable path" >&2
    exit 1
  fi
  cd "${repository_root}"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    "${bazel_binary}" build --macos_minimum_os=10.15 //:envoy-modsecurity
  else
    "${bazel_binary}" build //:envoy-modsecurity
  fi
fi

exec python3 "${repository_root}/tools/qualification-benchmark.py" \
  --envoy-binary "${envoy_binary}" \
  "$@"
