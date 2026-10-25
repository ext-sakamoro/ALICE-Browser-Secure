#!/usr/bin/env bash
# forbid_unsafe_fixture_test.sh — run the REAL forbid-unsafe check against the
# committed fixture workspace (gates/forbid-unsafe-fixture) and assert it flags
# every escape shape and nothing else. The fixture compiles cleanly (each
# escape is invisible to the compiler), so a regression that stops catching a
# shape makes this test fail. Unlike the dict-level --self-test, this exercises
# file discovery (dep-info) and cargo metadata, where the scanner bugs lived.
set -euo pipefail
cd "$(dirname "$0")/.."

FIX=gates/forbid-unsafe-fixture
ALLOW=gates/no-raw-open/unsafe-allow.toml

out=$(python3 scripts/forbid_unsafe_check.py --manifest "$FIX/Cargo.toml" --allow-file "$ALLOW" 2>&1) && rc=0 || rc=$?
echo "$out"

if [ "$rc" -ne 2 ]; then
  echo "FAIL: expected rc 2 (findings), got $rc" >&2
  exit 1
fi

# the set of flagged package names, exactly (the summary line is excluded)
got=$(printf '%s\n' "$out" | grep -v '^forbid_unsafe_check:' | sed -n 's/^\([a-z][a-z0-9_-]*\): .*/\1/p' | sort -u)
want=$(printf '%s\n' inc mac outside pm rawid tgt | sort -u)
if [ "$got" != "$want" ]; then
  echo "FAIL: flagged set mismatch" >&2
  echo "got:"  >&2; echo "$got"  >&2
  echo "want:" >&2; echo "$want" >&2
  exit 1
fi

# the clean caller must never be flagged
if printf '%s\n' "$out" | grep -q '^app:'; then
  echo "FAIL: app (the clean caller) was flagged" >&2
  exit 1
fi

echo "forbid_unsafe fixture test: ok (macro_rules / raw-ident / include! / dir-named-target / proc_macro-alias / excluded-path-dep all flagged, app clean)"
