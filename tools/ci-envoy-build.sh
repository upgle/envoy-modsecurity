#!/usr/bin/env bash

set -euo pipefail

apt-get update
apt-get install --yes autoconf automake libpcre2-dev libtool libyajl-dev make pkg-config

git config --global --add safe.directory "${PWD}"
git config --global --add safe.directory "${PWD}/envoy"
git config --global --add safe.directory "${PWD}/third_party/modsecurity"
git config --global --add safe.directory "${PWD}/third_party/coreruleset"

# ModSecurity uses distro PCRE2 and YAJL packages, so compile all Linux targets against the same
# container sysroot instead of mixing those libraries with Envoy's hermetic glibc.
export BAZEL_USE_HOST_SYSROOT=True

bazel --version
df --human-readable
bazel build //third_party:libmodsecurity
make check
