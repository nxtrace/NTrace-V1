#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CALLER_DIR="${PWD}"
RESULT_NAME="${1:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD)}"
RESULT_DIR="${PERF_RESULT_DIR:-${ROOT_DIR}/.cache/perf}"
BENCH_COUNT="${BENCH_COUNT:-10}"
BENCH_TIME="${BENCH_TIME:-1s}"
BENCH_GOMAXPROCS="${BENCH_GOMAXPROCS:-10}"

if [[ "${RESULT_DIR}" != /* ]]; then
  RESULT_DIR="${CALLER_DIR}/${RESULT_DIR}"
fi

mkdir -p "${RESULT_DIR}"

export GOMAXPROCS="${BENCH_GOMAXPROCS}"

(
  cd "${ROOT_DIR}"
  go test \
    -run '^$' \
    -bench '^Benchmark' \
    -benchmem \
    -benchtime "${BENCH_TIME}" \
    -count "${BENCH_COUNT}" \
    ./dn42 ./util ./trace ./trace/internal ./trace/mtu ./server ./internal/nali
) | tee "${RESULT_DIR}/${RESULT_NAME}.bench.txt"

echo "benchmark results: ${RESULT_DIR}/${RESULT_NAME}.bench.txt"
