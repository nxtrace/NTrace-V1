#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CALLER_DIR="${PWD}"
RESULT_NAME="${1:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD)}"
RESULT_DIR="${PERF_RESULT_DIR:-${ROOT_DIR}/.cache/perf}"
BUILD_DIR="$(mktemp -d)"

if [[ "${RESULT_DIR}" != /* ]]; then
  RESULT_DIR="${CALLER_DIR}/${RESULT_DIR}"
fi

cleanup() {
  rm -rf -- "${BUILD_DIR}"
}
trap cleanup EXIT

mkdir -p "${RESULT_DIR}"
OUTPUT_FILE="${RESULT_DIR}/${RESULT_NAME}.sizes.tsv"

printf 'flavor\tuncompressed_bytes\tupx_bytes\n' >"${OUTPUT_FILE}"

measure_flavor() {
  local flavor="$1"
  local tags="$2"
  local binary="${BUILD_DIR}/${flavor}"
  local -a tags_flag=()
  if [[ -n "${tags}" ]]; then
    tags_flag=(-tags "${tags}")
  fi

  go build -buildvcs=false -trimpath "${tags_flag[@]}" -ldflags '-s -w -buildid=' -o "${binary}" .

  local plain_size
  plain_size="$(wc -c <"${binary}" | tr -d ' ')"
  local upx_size="n/a"
  if [[ -n "${UPX_BIN:-}" ]]; then
    local packed="${binary}.upx"
    local -a upx_flags
    read -r -a upx_flags <<<"${UPX_FLAGS:--9}"
    cp "${binary}" "${packed}"
    if ! "${UPX_BIN}" "${upx_flags[@]}" "${packed}" >/dev/null; then
      echo "UPX failed for ${flavor}: ${UPX_BIN}" >&2
      return 1
    fi
    upx_size="$(wc -c <"${packed}" | tr -d ' ')"
  fi

  printf '%s\t%s\t%s\n' "${flavor}" "${plain_size}" "${upx_size}" >>"${OUTPUT_FILE}"
}

cd "${ROOT_DIR}"
measure_flavor nexttrace ''
measure_flavor nexttrace-tiny flavor_tiny
measure_flavor ntr flavor_ntr

cat "${OUTPUT_FILE}"
