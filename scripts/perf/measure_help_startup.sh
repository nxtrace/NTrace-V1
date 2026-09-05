#!/usr/bin/env bash

set -Eeuo pipefail

if (( $# < 3 || $# % 2 == 0 )); then
  echo "usage: $0 RESULT_NAME LABEL BINARY [LABEL BINARY ...]" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: startup and RSS measurement is supported on macOS only" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CALLER_DIR="${PWD}"
RESULT_NAME="$1"
RESULT_DIR="${PERF_RESULT_DIR:-${ROOT_DIR}/.cache/perf}"
STARTUP_RUNS="${STARTUP_RUNS:-10}"
shift

if [[ "${RESULT_DIR}" != /* ]]; then
  RESULT_DIR="${CALLER_DIR}/${RESULT_DIR}"
fi

mkdir -p "${RESULT_DIR}"
OUTPUT_FILE="${RESULT_DIR}/${RESULT_NAME}.startup.tsv"
printf 'flavor\tsample\telapsed_ns\tmax_rss_bytes\n' >"${OUTPUT_FILE}"

measure_elapsed_ns() {
  perl -MTime::HiRes=time -e '
    my $start = time();
    my $pid = fork();
    die "fork failed: $!\n" unless defined $pid;
    if ($pid == 0) {
      open STDOUT, ">", "/dev/null" or die "redirect stdout: $!\n";
      open STDERR, ">", "/dev/null" or die "redirect stderr: $!\n";
      exec {$ARGV[0]} $ARGV[0], "--help";
      die "exec failed: $!\n";
    }
    waitpid($pid, 0);
    die "command failed: $?\n" if $? != 0;
    printf "%.0f\n", (time() - $start) * 1_000_000_000;
  ' "$1"
}

while (( $# > 0 )); do
  label="$1"
  binary="$2"
  shift 2

  if [[ ! -x "${binary}" ]]; then
    echo "binary is not executable: ${binary}" >&2
    exit 1
  fi

  for ((sample = 1; sample <= STARTUP_RUNS; sample++)); do
    elapsed_ns="$(measure_elapsed_ns "${binary}")"
    rss_file="$(mktemp)"
    if ! /usr/bin/time -l "${binary}" --help >/dev/null 2>"${rss_file}"; then
      rm -f -- "${rss_file}"
      echo "help command failed: ${binary}" >&2
      exit 1
    fi
    max_rss_bytes="$(awk '/maximum resident set size/ { print $1; found = 1 } END { if (!found) exit 1 }' "${rss_file}")"
    rm -f -- "${rss_file}"
    printf '%s\t%d\t%s\t%s\n' "${label}" "${sample}" "${elapsed_ns}" "${max_rss_bytes}" >>"${OUTPUT_FILE}"
  done
done

cat "${OUTPUT_FILE}"
