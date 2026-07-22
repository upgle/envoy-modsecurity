#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -lt 2 ]]; then
  echo "Usage: $0 PATCH CONFIGURE [ARGUMENT ...]" >&2
  exit 2
fi

patch_file="$1"
shift

patch --batch --forward --strip=1 < "${patch_file}"
exec "$@"
