#!/usr/bin/env bash

set -euo pipefail

sudo apt-get update
sudo apt-get install --yes autoconf automake libpcre2-dev libtool libyajl-dev make pkg-config

git config --global --add safe.directory "${PWD}"
bazel --version
df --human-readable
make check
