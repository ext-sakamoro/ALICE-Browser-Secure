#!/usr/bin/env bash
# url_crate_test.sh — run the root url crate's tests and enforce a pass floor.
#
# `cargo test` runs the lib unit tests, the integration tests and the doctests,
# each printing a `test result: ok. N passed` line. We sum N across them and
# require at least MIN_PASSED, which also fails on 0 (nothing ran) — so a test
# binary silently dropping out of the build turns the job red instead of green.
#
# MIN_PASSED is the measured count; raise it when tests are added.
set -euo pipefail
cd "$(dirname "$0")/.."

MIN_PASSED=120

out=$(cargo test 2>&1)
printf '%s\n' "$out"

passed=$(printf '%s\n' "$out" \
  | sed -nE 's/^test result: ok\. ([0-9]+) passed.*/\1/p' \
  | awk '{ s += $1 } END { print s + 0 }')

echo "url-crate tests passed: ${passed} (floor ${MIN_PASSED})"
if [ "${passed}" -lt "${MIN_PASSED}" ]; then
  echo "FAIL: ${passed} passed is below the floor ${MIN_PASSED} (0 = nothing ran)" >&2
  exit 1
fi
