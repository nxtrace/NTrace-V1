#!/usr/bin/env bash

set -Eeuo pipefail

if [[ "$#" -lt 2 || "$#" -gt 3 ]]; then
  echo "Usage: $0 PACKAGE BENCHMARK [RESULT_NAME]" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CALLER_DIR="${PWD}"
PACKAGE="$1"
BENCHMARK="$2"
RESULT_NAME="${3:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD)}"
RESULT_DIR="${PERF_RESULT_DIR:-${ROOT_DIR}/.cache/perf}"
PROFILE_TIME="${PROFILE_TIME:-30s}"
BENCH_GOMAXPROCS="${BENCH_GOMAXPROCS:-10}"

if [[ "${RESULT_DIR}" != /* ]]; then
  RESULT_DIR="${CALLER_DIR}/${RESULT_DIR}"
fi

mkdir -p "${RESULT_DIR}"
export GOMAXPROCS="${BENCH_GOMAXPROCS}"

benchmark_list="$(
  cd "${ROOT_DIR}"
  go test -run '^$' -list "^${BENCHMARK}$" "${PACKAGE}"
)"
benchmark_found=false
while IFS= read -r name; do
  if [[ "${name}" == "${BENCHMARK}" ]]; then
    benchmark_found=true
    break
  fi
done <<<"${benchmark_list}"
if [[ "${benchmark_found}" != true ]]; then
  echo "Benchmark not found in ${PACKAGE}: ${BENCHMARK}" >&2
  exit 1
fi

(
  cd "${ROOT_DIR}"
  go test \
    -run '^$' \
    -bench "^${BENCHMARK}$" \
    -benchtime "${PROFILE_TIME}" \
    -count 1 \
    -cpuprofile "${RESULT_DIR}/${RESULT_NAME}.cpu.pprof" \
    -memprofile "${RESULT_DIR}/${RESULT_NAME}.heap.pprof" \
    "${PACKAGE}"
)

echo "CPU profile: ${RESULT_DIR}/${RESULT_NAME}.cpu.pprof"
echo "heap profile: ${RESULT_DIR}/${RESULT_NAME}.heap.pprof"
