#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1091
source "${repository_root}/DEPENDENCIES.lock"

verify_pin() {
  local component="$1"
  local path="$2"
  local version="$3"
  local expected="$4"

  if [[ ! -e "${repository_root}/${path}/.git" ]]; then
    echo "${component} ${version}: submodule is not initialized at ${path}" >&2
    return 1
  fi

  local actual
  actual="$(git -C "${repository_root}/${path}" rev-parse HEAD)"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "${component} ${version}: expected ${expected}, found ${actual}" >&2
    return 1
  fi

  echo "${component} ${version}: ${actual}"
}

verify_pin "Envoy" "envoy" "${ENVOY_VERSION}" "${ENVOY_COMMIT}"
verify_pin "ModSecurity" "third_party/modsecurity" "${MODSECURITY_VERSION}" \
  "${MODSECURITY_COMMIT}"
verify_pin "OWASP CRS" "third_party/coreruleset" "${CORERULESET_VERSION}" \
  "${CORERULESET_COMMIT}"
