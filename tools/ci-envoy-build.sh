#!/usr/bin/env bash

set -euo pipefail

apt-get update
apt-get install --yes autoconf automake libpcre2-dev libtool libyajl-dev make pkg-config

git config --global --add safe.directory "${PWD}"
git config --global --add safe.directory "${PWD}/envoy"
git config --global --add safe.directory "${PWD}/third_party/modsecurity"
git config --global --add safe.directory "${PWD}/third_party/coreruleset"
bazel --version
df --human-readable
if ! bazel build --sandbox_debug //third_party:libmodsecurity; then
  find /build/.cache/bazel \
    -type f \
    -name config.log \
    -path '*libmodsecurity*' \
    -print \
    -exec tail --lines=200 {} \;
  exit 1
fi
make check
