#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The CI WAF comparison requires Linux x86_64." >&2
  exit 2
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
comparison_target="//test/performance/envoy_dynamic_comparison:envoy-waf-comparison"
comparison_binary="${repository_root}/bazel-bin/test/performance/envoy_dynamic_comparison/envoy-waf-comparison"
coraza_module="${CORAZA_MODULE:?CORAZA_MODULE must point to libcomposer.so}"
benchmark_repeats="${BENCHMARK_REPEATS:-7}"
benchmark_request_scale="${BENCHMARK_REQUEST_SCALE:-3}"
pgo_training_request_scale="${PGO_TRAINING_REQUEST_SCALE:-1}"
output_directory="${repository_root}/artifacts/waf-engine-comparison"
pgo_root="${HOME}/waf-comparison-pgo"
raw_profile_directory="${pgo_root}/raw"
merged_profile="${pgo_root}/waf-comparison.profdata"
training_output_directory="${pgo_root}/training-report"

if [[ ! -f "${coraza_module}" ]]; then
  echo "Comparison module does not exist: ${coraza_module}" >&2
  exit 2
fi

apt-get update
apt-get install --yes \
  autoconf \
  automake \
  curl \
  libpcre2-dev \
  libtool \
  libxml2-dev \
  libyajl-dev \
  make \
  pkg-config

export CI_SYSROOT_FINGERPRINT="$({
  printf '%s\n' "${ENVOY_BUILD_IMAGE:?ENVOY_BUILD_IMAGE must be set}"
  dpkg-query --show \
    --showformat='${binary:Package}=${Version}\n' \
    autoconf automake libpcre2-dev libtool libxml2-dev libyajl-dev make pkg-config
} | sha256sum | cut --delimiter=' ' --fields=1)"

buildbuddy_bazelrc="${HOME}/.bazelrc"
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
  umask "${previous_umask}"
  trap 'rm -f -- "${buildbuddy_bazelrc}"' EXIT
  echo "BuildBuddy remote cache enabled for the comparison build."
else
  echo "BuildBuddy API key unavailable; continuing without the remote cache."
fi

git config --global --add safe.directory "${repository_root}"
git config --global --add safe.directory "${repository_root}/envoy"
git config --global --add safe.directory "${repository_root}/third_party/modsecurity"
git config --global --add safe.directory "${repository_root}/third_party/coreruleset"

# The native dependency uses packages from the container sysroot. Keep the same sysroot contract as
# the main Linux build, including across the instrumented and profile-use configurations.
export BAZEL_USE_HOST_SYSROOT=True

cd "${repository_root}"
make verify-deps
mkdir --parents "${raw_profile_directory}" "${output_directory}"

common_build_flags=(
  --compilation_mode=opt
  --strip=always
  --fission=no
  --features=-per_object_debug_info
  '--per_file_copt=.*@-flto=thin'
  --linkopt=-flto=thin
  --nocheck_visibility
)

echo "Building the Linux release ThinLTO instrumentation binary."
bazel build \
  "${common_build_flags[@]}" \
  --define=modsecurity_benchmark_pgo=instrument \
  --fdo_instrument="${raw_profile_directory}" \
  "${comparison_target}"

echo "Training the profile across baseline and both filter paths."
python3 tools/waf-engine-comparison.py \
  --envoy-binary "${comparison_binary}" \
  --coraza-module "${coraza_module}" \
  --output-directory "${training_output_directory}" \
  --repeats 1 \
  --request-scale "${pgo_training_request_scale}" \
  --build-profile "Linux release ThinLTO PGO instrumentation training" \
  --coraza-release v0.6.2 \
  --coraza-engine-version v3.7.0 \
  --libmodsecurity-version v3.0.16 \
  --crs-version v4.28.0

mapfile -d '' -t raw_profiles < <(
  find "${raw_profile_directory}" -type f -name '*.profraw' -print0
)
if [[ "${#raw_profiles[@]}" -eq 0 ]]; then
  echo "The training run did not produce any LLVM raw profiles." >&2
  exit 1
fi

llvm_profdata="$(bazel info output_base)/external/llvm_toolchain/bin/llvm-profdata"
if [[ ! -x "${llvm_profdata}" && -x /opt/llvm/bin/llvm-profdata ]]; then
  llvm_profdata=/opt/llvm/bin/llvm-profdata
fi
if [[ ! -x "${llvm_profdata}" ]]; then
  llvm_profdata="$(command -v llvm-profdata || true)"
fi
if [[ -z "${llvm_profdata}" ]]; then
  echo "llvm-profdata is required to merge the PGO training profiles." >&2
  exit 1
fi

"${llvm_profdata}" merge --output="${merged_profile}" "${raw_profiles[@]}"
"${llvm_profdata}" show --detailed-summary --profile-version "${merged_profile}" \
  > "${output_directory}/pgo-profile-summary.txt"
merged_profile_sha256="$(sha256sum "${merged_profile}" | cut --delimiter=' ' --fields=1)"

echo "Building the Linux release ThinLTO binary with the merged PGO profile."
bazel build \
  "${common_build_flags[@]}" \
  --action_env=MODSECURITY_PGO_PROFILE_SHA256="${merged_profile_sha256}" \
  --define=modsecurity_benchmark_pgo=use \
  --fdo_optimize="${merged_profile}" \
  "${comparison_target}"

python3 tools/waf-engine-comparison.py \
  --envoy-binary "${comparison_binary}" \
  --coraza-module "${coraza_module}" \
  --output-directory "${output_directory}" \
  --repeats "${benchmark_repeats}" \
  --request-scale "${benchmark_request_scale}" \
  --build-profile "Linux x86_64 Bazel opt, stripped, ThinLTO, instrumentation PGO" \
  --coraza-release v0.6.2 \
  --coraza-engine-version v3.7.0 \
  --libmodsecurity-version v3.0.16 \
  --crs-version v4.28.0

{
  printf 'target=%s\n' "${comparison_target}"
  printf 'bazel_version=%s\n' "$(bazel --version)"
  printf 'llvm_profdata_version=%s\n' "$("${llvm_profdata}" --version | head --lines=1)"
  printf 'build_flags=%s\n' "${common_build_flags[*]} --define=modsecurity_benchmark_pgo=use --fdo_optimize=<merged LLVM profile>"
  printf 'raw_profile_count=%s\n' "${#raw_profiles[@]}"
  printf 'merged_profile_sha256=%s\n' "${merged_profile_sha256}"
  printf 'envoy_binary_sha256=%s\n' "$(sha256sum "${comparison_binary}" | cut --delimiter=' ' --fields=1)"
  printf 'comparison_module_sha256=%s\n' "$(sha256sum "${coraza_module}" | cut --delimiter=' ' --fields=1)"
} > "${output_directory}/build-manifest.txt"
