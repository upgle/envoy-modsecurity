#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
benchmark_runner="${QUALIFICATION_BENCHMARK_RUNNER:-${repository_root}/tools/run-qualification-benchmark.sh}"
output_directory="${QUALIFICATION_OUTPUT_DIRECTORY:-${repository_root}/artifacts/qualification-benchmark}"

if [[ ! -x "${benchmark_runner}" ]]; then
  echo "qualification benchmark runner is not executable: ${benchmark_runner}" >&2
  exit 2
fi

mkdir -p "${output_directory}"
rm -f \
  "${output_directory}/qualification-benchmark.json" \
  "${output_directory}/qualification-benchmark.md"

run_attempt() {
  local attempt="$1"
  local attempt_directory="${output_directory}/attempt-${attempt}"
  local status=0

  mkdir -p "${attempt_directory}"
  rm -f \
    "${attempt_directory}/qualification-benchmark.json" \
    "${attempt_directory}/qualification-benchmark.md"

  "${benchmark_runner}" \
    --enforce \
    --output-directory "${attempt_directory}" || status=$?

  if (( status == 0 || status == 1 )); then
    if [[ ! -f "${attempt_directory}/qualification-benchmark.json" ||
          ! -f "${attempt_directory}/qualification-benchmark.md" ]]; then
      echo "qualification attempt ${attempt} did not produce complete reports" >&2
      return 2
    fi
  fi
  return "${status}"
}

publish_attempt() {
  local attempt="$1"
  local attempt_directory="${output_directory}/attempt-${attempt}"

  cp \
    "${attempt_directory}/qualification-benchmark.json" \
    "${attempt_directory}/qualification-benchmark.md" \
    "${output_directory}/"
}

first_status=0
run_attempt 1 || first_status=$?
case "${first_status}" in
  0)
    publish_attempt 1
    exit 0
    ;;
  1)
    echo "Qualification performance thresholds exceeded; retrying once on a fresh Envoy process."
    ;;
  *)
    exit "${first_status}"
    ;;
esac

second_status=0
run_attempt 2 || second_status=$?
if (( second_status == 0 || second_status == 1 )); then
  publish_attempt 2
fi
exit "${second_status}"
