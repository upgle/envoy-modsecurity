#!/usr/bin/env bash

set -euo pipefail

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
  printf '%s\n' \
    'build --bes_results_url=https://app.buildbuddy.io/invocation/' \
    'build --bes_backend=grpcs://remote.buildbuddy.io' \
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
bazel build //third_party:libmodsecurity
make check
./tools/run-crs-compatibility.sh
