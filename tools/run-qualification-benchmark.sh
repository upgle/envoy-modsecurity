#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
envoy_binary="${repository_root}/bazel-bin/envoy-modsecurity"

if [[ ! -x "${envoy_binary}" ]]; then
  bazel_binary="$(command -v bazel || true)"
  if [[ -z "${bazel_binary}" ]]; then
    bazel_binary="/Users/seonghyun/Library/Caches/bazelisk/downloads/sha256/575f20fb23955e02f73519befd180df635b4ed0960c60f0e70fcc8d74014a713/bin/bazel"
  fi
  if [[ "$(uname -s)" == "Darwin" ]]; then
    "${bazel_binary}" build --macos_minimum_os=10.15 //:envoy-modsecurity
  else
    "${bazel_binary}" build //:envoy-modsecurity
  fi
fi

exec python3 "${repository_root}/tools/qualification-benchmark.py" \
  --envoy-binary "${envoy_binary}" \
  "$@"
