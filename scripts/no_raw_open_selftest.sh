#!/usr/bin/env bash
# no_raw_open_selftest.sh — prove the shipped clippy `disallowed-methods` gate
# flags every way to launch a URL from a string.
#
# It lints gates/no-raw-open/bypasses with the shipped gates/no-raw-open/clippy.toml
# and checks that clippy's `disallowed_methods` count equals the number of
# `// FINDING` lines in the fixture (and so is > 0), while the one opener marked
# `#[allow(clippy::disallowed_methods)]` is NOT counted.
#
# A fresh target dir is used so clippy re-emits (a cached build is silent).
set -euo pipefail
cd "$(dirname "$0")/.."

fix="gates/no-raw-open"
src="$fix/bypasses/src/lib.rs"

expected=$(grep -c '// FINDING' "$src")
if [ "$expected" -le 0 ]; then
  echo "no-raw-open self-test: 0 FINDING markers in the fixture (nothing to compare)" >&2
  exit 1
fi

tmp_target=$(mktemp -d "${TMPDIR:-/tmp}/no-raw-open-XXXXXX")
trap 'rm -rf "$tmp_target"' EXIT

json=$(cd "$fix" && CARGO_TARGET_DIR="$tmp_target" \
  cargo clippy -p bypasses --message-format=json -- -W clippy::disallowed_methods 2>/dev/null)

got=$(printf '%s' "$json" | python3 -c '
import sys, json
n = 0
for line in sys.stdin:
    line = line.strip()
    if not line or line[0] != "{":
        continue
    try:
        m = json.loads(line)
    except Exception:
        continue
    msg = m.get("message") or {}
    code = (msg.get("code") or {}).get("code")
    if code == "clippy::disallowed_methods" and msg.get("level") in ("warning", "error"):
        n += 1
print(n)
')

echo "no-raw-open self-test: disallowed_methods findings=${got}, expected (// FINDING)=${expected}"
if [ "${got}" != "${expected}" ]; then
  echo "FAIL: clippy flagged ${got}, expected ${expected} (a bypass escaped, or the allowed opener was flagged)" >&2
  exit 1
fi
echo "no-raw-open self-test: ok"
