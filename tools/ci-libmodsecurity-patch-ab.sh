#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The libmodsecurity patch A/B benchmark requires Linux x86_64." >&2
  exit 2
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
comparison_target="//test/performance/envoy_dynamic_comparison:envoy-waf-comparison"
comparison_binary="${repository_root}/bazel-bin/test/performance/envoy_dynamic_comparison/envoy-waf-comparison"
benchmark_repeats="${BENCHMARK_REPEATS:-10}"
benchmark_request_scale="${BENCHMARK_REQUEST_SCALE:-5}"
output_directory="${repository_root}/artifacts/libmodsecurity-patch-ab"
binary_directory="${HOME}/libmodsecurity-patch-ab"
patched_binary="${binary_directory}/envoy-patched"
unpatched_binary="${binary_directory}/envoy-unpatched"

if (( benchmark_repeats < 2 || benchmark_repeats % 2 != 0 )); then
  echo "BENCHMARK_REPEATS must be an even integer of at least 2." >&2
  exit 2
fi

mkdir --parents "${output_directory}"
lscpu > "${output_directory}/runner-cpu.txt"
{
  printf 'envoy_build_image=%s\n' "${ENVOY_BUILD_IMAGE:?ENVOY_BUILD_IMAGE must be set}"
  printf 'repeats=%s\n' "${benchmark_repeats}"
  printf 'request_scale=%s\n' "${benchmark_request_scale}"
} > "${output_directory}/build-manifest.txt"

buildbuddy_bazelrc="${HOME}/.bazelrc"
buildbuddy_bazelrc_created=false
cleanup() {
  if [[ "${buildbuddy_bazelrc_created}" == true ]]; then
    rm -f -- "${buildbuddy_bazelrc}"
  fi
  chmod --recursive a+rX "${output_directory}" || true
}
trap cleanup EXIT

apt-get update
apt-get install --yes \
  autoconf \
  automake \
  libpcre2-dev \
  libtool \
  libxml2-dev \
  libyajl-dev \
  make \
  patch \
  pkg-config

dpkg-query --show \
  --showformat='${binary:Package}=${Version}\n' \
  autoconf automake libpcre2-dev libtool libxml2-dev libyajl-dev make patch pkg-config \
  > "${output_directory}/system-packages.txt"
export CI_SYSROOT_FINGERPRINT="$({
  printf '%s\n' "${ENVOY_BUILD_IMAGE}"
  cat "${output_directory}/system-packages.txt"
} | sha256sum | cut --delimiter=' ' --fields=1)"
printf 'ci_sysroot_fingerprint=%s\n' "${CI_SYSROOT_FINGERPRINT}" \
  >> "${output_directory}/build-manifest.txt"

if [[ -n "${BUILDBUDDY_API_KEY:-}" ]]; then
  previous_umask="$(umask)"
  umask 077
  printf '%s\n' \
    'build --bes_results_url=https://app.buildbuddy.io/invocation/' \
    'build --bes_backend=grpcs://remote.buildbuddy.io' \
    'build --bes_upload_mode=fully_async' \
    'common --remote_cache=grpcs://remote.buildbuddy.io' \
    "common --remote_header=x-buildbuddy-api-key=${BUILDBUDDY_API_KEY}" \
    'common --remote_cache_compression' \
    'common --remote_timeout=60s' \
    'build --action_env=CI_SYSROOT_FINGERPRINT' \
    > "${buildbuddy_bazelrc}"
  buildbuddy_bazelrc_created=true
  umask "${previous_umask}"
  echo "BuildBuddy remote cache enabled for the A/B build."
else
  echo "BuildBuddy API key unavailable; continuing without the remote cache."
fi

git config --global --add safe.directory "${repository_root}"
git config --global --add safe.directory "${repository_root}/envoy"
git config --global --add safe.directory "${repository_root}/third_party/modsecurity"
git config --global --add safe.directory "${repository_root}/third_party/coreruleset"

export BAZEL_USE_HOST_SYSROOT=True

cd "${repository_root}"
make verify-deps
mkdir --parents "${binary_directory}"

common_build_flags=(
  --compilation_mode=opt
  --define=modsecurity_benchmark_thinlto=enabled
  --fission=no
  --features=-per_object_debug_info
  '--per_file_copt=.*@-flto=thin'
  --linkopt=-flto=thin
  --nocheck_visibility
  --strip=always
)
semantic_test_targets=(
  //test/engine:rules_test
  //test/engine:engine_integration_test
  //test/unit:filter_test
)

{
  printf 'project_commit=%s\n' "$(git rev-parse HEAD)"
  printf 'libmodsecurity_commit=%s\n' "$(git -C third_party/modsecurity rev-parse HEAD)"
  printf 'crs_commit=%s\n' "$(git -C third_party/coreruleset rev-parse HEAD)"
  printf 'patch_sha256=%s\n' "$(sha256sum bazel/libmodsecurity-connector-optimizations.patch | cut --delimiter=' ' --fields=1)"
  printf 'target=%s\n' "${comparison_target}"
  printf 'bazel_version=%s\n' "$(bazel --version)"
  printf 'build_flags=%s\n' "${common_build_flags[*]}"
  printf 'pgo=disabled\n'
  printf 'patched_define=--define=libmodsecurity_connector_optimizations=enabled\n'
  printf 'unpatched_define=--define=libmodsecurity_connector_optimizations=disabled\n'
} >> "${output_directory}/build-manifest.txt"

echo "Building the unpatched Linux release ThinLTO control."
bazel build \
  "${common_build_flags[@]}" \
  --define=libmodsecurity_connector_optimizations=disabled \
  "${comparison_target}"
install --mode=0755 "${comparison_binary}" "${unpatched_binary}"
output_base="$(bazel info output_base)"
clang_binary="${output_base}/external/llvm_toolchain_llvm/bin/clang"
lld_binary="${output_base}/external/llvm_toolchain/bin/ld.lld"
{
  if [[ -x "${clang_binary}" ]]; then
    "${clang_binary}" --version
  else
    printf 'clang unavailable at %s\n' "${clang_binary}"
  fi
  if [[ -x "${lld_binary}" ]]; then
    "${lld_binary}" --version
  else
    printf 'ld.lld unavailable at %s\n' "${lld_binary}"
  fi
} > "${output_directory}/llvm-toolchain.txt"
printf 'unpatched_binary_sha256=%s\n' \
  "$(sha256sum "${unpatched_binary}" | cut --delimiter=' ' --fields=1)" \
  >> "${output_directory}/build-manifest.txt"
bazel test \
  "${common_build_flags[@]}" \
  --define=libmodsecurity_connector_optimizations=disabled \
  "${semantic_test_targets[@]}"
printf 'unpatched_semantic_tests=passed\n' \
  >> "${output_directory}/build-manifest.txt"

echo "Building the patched Linux release ThinLTO candidate."
bazel build \
  "${common_build_flags[@]}" \
  --define=libmodsecurity_connector_optimizations=enabled \
  "${comparison_target}"
install --mode=0755 "${comparison_binary}" "${patched_binary}"
printf 'patched_binary_sha256=%s\n' \
  "$(sha256sum "${patched_binary}" | cut --delimiter=' ' --fields=1)" \
  >> "${output_directory}/build-manifest.txt"
bazel test \
  "${common_build_flags[@]}" \
  --define=libmodsecurity_connector_optimizations=enabled \
  "${semantic_test_targets[@]}"
printf 'patched_semantic_tests=passed\n' \
  >> "${output_directory}/build-manifest.txt"

if cmp --silent "${patched_binary}" "${unpatched_binary}"; then
  echo "The patched and unpatched binaries are unexpectedly identical." >&2
  exit 1
fi

python3 tools/waf-engine-comparison.py \
  --libmodsecurity-patch-ab \
  --envoy-binary "${patched_binary}" \
  --reference-envoy-binary "${unpatched_binary}" \
  --output-directory "${output_directory}" \
  --run-log-directory "${output_directory}/logs" \
  --repeats "${benchmark_repeats}" \
  --request-scale "${benchmark_request_scale}" \
  --build-profile "Linux x86_64 Bazel opt, stripped, ThinLTO, no PGO" \
  --libmodsecurity-version v3.0.16 \
  --crs-version v4.28.0 \
  --workload headers_c1 \
  --workload clean_query_c1 \
  --workload form_1k_c1 \
  --workload json_4k_c1 \
  --workload blocked_sqli_c1 \
  --workload blocked_xss_c1 \
  --workload phase1_block_c1 \
  --workload headers_c16 \
  --workload blocked_sqli_c16 \
  --workload phase1_block_c16 \
  2>&1 | tee "${output_directory}/benchmark.log"
