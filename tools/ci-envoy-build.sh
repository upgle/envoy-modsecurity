#!/usr/bin/env bash

set -euo pipefail

ci_mode="${1:-all}"
case "${ci_mode}" in
  all | build | qa | sanitizers) ;;
  *)
    echo "Usage: $0 [all|build|qa|sanitizers]" >&2
    exit 2
    ;;
esac

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

# The native ModSecurity build consumes packages from the container sysroot. Include the pinned
# image and installed package versions in every action key so remote results cannot cross sysroots.
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
  # Keep BuildBuddy telemetry best-effort so a backend acknowledgement failure cannot override a
  # successful build or test result. Remote cache operations remain synchronous and independent.
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
  echo "BuildBuddy remote cache enabled for CI."
else
  echo "BuildBuddy API key unavailable; continuing without the remote cache."
fi

git config --global --add safe.directory "${PWD}"
git config --global --add safe.directory "${PWD}/envoy"
git config --global --add safe.directory "${PWD}/third_party/modsecurity"
git config --global --add safe.directory "${PWD}/third_party/coreruleset"

# ModSecurity uses distro PCRE2, LibXML2, and YAJL packages, so compile all Linux targets against
# the same container sysroot instead of mixing those libraries with Envoy's hermetic glibc.
export BAZEL_USE_HOST_SYSROOT=True

bazel --version
df --human-readable

run_build() {
  make verify-deps
  bazel build \
    //:api_bindings \
    //:envoy-modsecurity \
    //source/extensions/filters/http/modsecurity:config \
    //third_party:libmodsecurity
}

run_qa() {
  make check
  ./tools/run-crs-compatibility.sh --apply-platform-overrides --fail-on-test-failure
  ./tools/run-qualification-benchmark.sh --enforce
}

preserve_sanitizer_logs() {
  local sanitizer_name="$1"
  local target
  local test_log
  local relative_path
  shift

  for target in "$@"; do
    if [[ "${target}" != //*:* ]]; then
      continue
    fi
    relative_path="${target#//}"
    relative_path="${relative_path%%:*}/${relative_path#*:}/test.log"
    test_log="bazel-testlogs/${relative_path}"
    if [[ -f "${test_log}" ]]; then
      mkdir -p "artifacts/sanitizers/${sanitizer_name}/$(dirname "${relative_path}")"
      cp "${test_log}" "artifacts/sanitizers/${sanitizer_name}/${relative_path}"
    fi
  done
}

run_sanitizer_suite() {
  local sanitizer_name="$1"
  local status=0
  shift

  bazel test --nocache_test_results "$@" || status=$?
  preserve_sanitizer_logs "${sanitizer_name}" "$@"
  return "${status}"
}

# AddressSanitizer also enables Envoy's undefined-behavior sanitizer flags. On Linux, leak
# detection remains enabled by the sanitizer runtime. The in-process protocol and ECDS suites cover
# reset, body accounting, multi-worker publication, and generation reclamation paths.
run_sanitizers() {
  make verify-deps

  run_sanitizer_suite asan -c dbg --config=asan \
    //test/engine:engine_integration_test \
    //test/integration:filter_ecds_integration_test \
    //test/integration:filter_protocol_integration_test \
    //test/unit:config_test \
    //test/unit:filter_test

  # Exercise native transaction and rule-generation churn with the thread sanitizer separately
  # from the larger HTTP suites so the race gate stays focused and has a bounded runtime.
  run_sanitizer_suite tsan -c dbg --config=tsan \
    //test/engine:engine_integration_test \
    //test/integration:filter_ecds_integration_test \
    //test/unit:filter_test
}

case "${ci_mode}" in
  build)
    run_build
    ;;
  qa)
    run_qa
    ;;
  sanitizers)
    run_sanitizers
    ;;
  all)
    run_build
    run_qa
    run_sanitizers
    ;;
esac
