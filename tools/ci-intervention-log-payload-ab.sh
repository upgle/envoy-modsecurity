#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The intervention log payload A/B benchmark requires Linux x86_64." >&2
  exit 2
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
benchmark_repeats="${BENCHMARK_REPEATS:-10}"
benchmark_request_scale="${BENCHMARK_REQUEST_SCALE:-5}"
baseline_revision="7ea9fefbe0ba409d8733b4d682c8c4c059cd028d"
candidate_revision="1e16589865de2d8d244741e0b9d219e59941bd80"
baseline_patch="${repository_root}/tools/intervention-log-payload-baseline.patch"
binary_directory="${HOME}/intervention-log-payload-ab"
baseline_binary="${binary_directory}/envoy-baseline"
candidate_binary="${binary_directory}/envoy-candidate"
output_directory="${repository_root}/artifacts/intervention-log-payload-ab"
project_binary="${repository_root}/bazel-bin/envoy-modsecurity"
baseline_patch_applied=false
buildbuddy_bazelrc="${HOME}/.bazelrc"
buildbuddy_bazelrc_created=false

if (( benchmark_repeats < 2 || benchmark_repeats % 2 != 0 )); then
  echo "BENCHMARK_REPEATS must be an even integer of at least 2." >&2
  exit 2
fi

mkdir --parents "${binary_directory}" "${output_directory}"
lscpu > "${output_directory}/runner-cpu.txt"

restore_candidate_source() {
  if [[ "${baseline_patch_applied}" == true ]]; then
    git -C "${repository_root}" apply --reverse "${baseline_patch}" || true
    baseline_patch_applied=false
  fi
  git -C "${repository_root}/third_party/modsecurity" checkout --quiet "${candidate_revision}" || true
  if [[ "${buildbuddy_bazelrc_created}" == true ]]; then
    rm -f -- "${buildbuddy_bazelrc}"
  fi
  chmod --recursive a+rX "${output_directory}" || true
}
trap restore_candidate_source EXIT

apt-get update
apt-get install --yes \
  autoconf \
  automake \
  libpcre2-dev \
  libtool \
  libxml2-dev \
  libyajl-dev \
  make \
  pkg-config

dpkg-query --show \
  --showformat='${binary:Package}=${Version}\n' \
  autoconf automake libpcre2-dev libtool libxml2-dev libyajl-dev make pkg-config \
  > "${output_directory}/system-packages.txt"

export CI_SYSROOT_FINGERPRINT="$({
  printf '%s\n' "${ENVOY_BUILD_IMAGE:?ENVOY_BUILD_IMAGE must be set}"
  cat "${output_directory}/system-packages.txt"
} | sha256sum | cut --delimiter=' ' --fields=1)"

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
actual_candidate_revision="$(git -C third_party/modsecurity rev-parse HEAD)"
if [[ "${actual_candidate_revision}" != "${candidate_revision}" ]]; then
  echo "Unexpected candidate dependency revision: ${actual_candidate_revision}" >&2
  exit 1
fi

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

{
  printf 'project_checkout_commit=%s\n' "$(git rev-parse HEAD)"
  printf 'project_head_commit=%s\n' "${GITHUB_HEAD_SHA:-$(git rev-parse HEAD)}"
  printf 'baseline_modsecurity_commit=%s\n' "${baseline_revision}"
  printf 'candidate_modsecurity_commit=%s\n' "${candidate_revision}"
  printf 'crs_commit=%s\n' "$(git -C third_party/coreruleset rev-parse HEAD)"
  printf 'baseline_patch_sha256=%s\n' "$(sha256sum "${baseline_patch}" | cut --delimiter=' ' --fields=1)"
  printf 'envoy_build_image=%s\n' "${ENVOY_BUILD_IMAGE}"
  printf 'ci_sysroot_fingerprint=%s\n' "${CI_SYSROOT_FINGERPRINT}"
  printf 'bazel_version=%s\n' "$(bazel --version)"
  printf 'build_flags=%s\n' "${common_build_flags[*]}"
  printf 'repeats=%s\n' "${benchmark_repeats}"
  printf 'request_scale=%s\n' "${benchmark_request_scale}"
  printf 'pgo=disabled\n'
} > "${output_directory}/build-manifest.txt"

echo "Building the Linux release ThinLTO baseline."
git -C third_party/modsecurity fetch --quiet --depth=1 origin "${baseline_revision}"
git -C third_party/modsecurity checkout --quiet "${baseline_revision}"
git apply "${baseline_patch}"
baseline_patch_applied=true
bazel build "${common_build_flags[@]}" //:envoy-modsecurity
install --mode=0755 "${project_binary}" "${baseline_binary}"
printf 'baseline_binary_sha256=%s\n' \
  "$(sha256sum "${baseline_binary}" | cut --delimiter=' ' --fields=1)" \
  >> "${output_directory}/build-manifest.txt"

echo "Building the Linux release ThinLTO candidate."
git apply --reverse "${baseline_patch}"
baseline_patch_applied=false
git -C third_party/modsecurity checkout --quiet "${candidate_revision}"
bazel build "${common_build_flags[@]}" //:envoy-modsecurity
install --mode=0755 "${project_binary}" "${candidate_binary}"
printf 'candidate_binary_sha256=%s\n' \
  "$(sha256sum "${candidate_binary}" | cut --delimiter=' ' --fields=1)" \
  >> "${output_directory}/build-manifest.txt"

git diff --exit-code -- source/engine/engine.cc
if cmp --silent "${baseline_binary}" "${candidate_binary}"; then
  echo "The baseline and candidate binaries are unexpectedly identical." >&2
  exit 1
fi

python3 tools/intervention-log-payload-benchmark.py \
  --baseline-envoy-binary "${baseline_binary}" \
  --candidate-envoy-binary "${candidate_binary}" \
  --output-directory "${output_directory}" \
  --run-log-directory "${output_directory}/logs" \
  --repeats "${benchmark_repeats}" \
  --request-scale "${benchmark_request_scale}" \
  --build-profile "Linux x86_64 Bazel opt, stripped, ThinLTO, no PGO" \
  --baseline-revision "${baseline_revision}" \
  --candidate-revision "${candidate_revision}" \
  2>&1 | tee "${output_directory}/benchmark.log"
