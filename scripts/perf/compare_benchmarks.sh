#!/usr/bin/env bash

set -Eeuo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "Usage: $0 BASE.bench.txt HEAD.bench.txt" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CALLER_DIR="${PWD}"

resolve_input_path() {
  local path="$1"
  if [[ "${path}" == /* ]]; then
    printf '%s\n' "${path}"
    return
  fi
  printf '%s/%s\n' "${CALLER_DIR}" "${path}"
}

BASE_FILE="$(resolve_input_path "$1")"
HEAD_FILE="$(resolve_input_path "$2")"

(
  cd "${ROOT_DIR}"
  go tool benchstat "${BASE_FILE}" "${HEAD_FILE}"
)
