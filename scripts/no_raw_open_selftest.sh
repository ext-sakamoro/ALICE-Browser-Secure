#!/usr/bin/env bash
# no_raw_open_selftest.sh — prove the shipped clippy gate flags every way to
# launch a URL from a string, by LINE, not by count.
#
# It lints gates/no-raw-open/bypasses with the shipped gates/no-raw-open/clippy.toml
# and requires: the SET of lines clippy flags (disallowed_types + disallowed_methods)
# equals the SET of lines marked `// FINDING`, and the `// ALLOWED` opener line
# is NOT flagged. Comparing sets (not totals) means a false flag on one line and
# an escape on another cannot cancel out.
#
# A fresh target dir is used so clippy re-emits (a cached build is silent).
set -euo pipefail
cd "$(dirname "$0")/.."

fix="gates/no-raw-open"
src="$fix/bypasses/src/lib.rs"

tmp_target=$(mktemp -d "${TMPDIR:-/tmp}/no-raw-open-XXXXXX")
trap 'rm -rf "$tmp_target"' EXIT

json=$(cd "$fix" && CARGO_TARGET_DIR="$tmp_target" \
  cargo clippy -p bypasses --message-format=json -- \
    -W clippy::disallowed_methods -W clippy::disallowed_types 2>/dev/null)

SRC="$src" python3 - "$json" <<'PY'
import os, sys, json

src = os.environ["SRC"]
# clippy reports file_name relative to the fixture workspace (the cwd of the
# clippy run); match the bypasses crate only, not every crate's lib.rs — the
# stub crates legitimately define `impl Command` for the disallowed types.
want_suffix = "bypasses/src/lib.rs"

expected = set()
allowed = set()
with open(src, encoding="utf-8") as f:
    for i, line in enumerate(f, 1):
        is_code = not line.lstrip().startswith("//")  # not a comment-only/doc line
        # tolerate trailing text after the marker (e.g. `// FINDING  (note)`);
        # detect by substring so no marker line is skipped silently
        if is_code and "// FINDING" in line:
            expected.add(i)
        if is_code and "// ALLOWED" in line:
            allowed.add(i)

flagged = set()
for raw in sys.argv[1].splitlines():
    raw = raw.strip()
    if not raw or raw[0] != "{":
        continue
    try:
        m = json.loads(raw)
    except Exception:
        continue
    msg = m.get("message") or {}
    code = (msg.get("code") or {}).get("code")
    if code not in ("clippy::disallowed_methods", "clippy::disallowed_types"):
        continue
    if msg.get("level") not in ("warning", "error"):
        continue
    for sp in msg.get("spans") or []:
        fn = sp.get("file_name", "").replace("\\", "/")
        if sp.get("is_primary") and fn.endswith(want_suffix):
            flagged.add(sp["line_start"])

ok = True
if not expected:
    print("self-test: no // FINDING markers (nothing to compare)", file=sys.stderr)
    ok = False
missing = sorted(expected - flagged)   # a disallowed call the gate did NOT flag
extra = sorted(flagged - expected)     # a line flagged that was not marked
hit_allowed = sorted(flagged & allowed)
if missing:
    print(f"self-test FAIL: {len(missing)} marked line(s) NOT flagged (a bypass escaped): {missing}", file=sys.stderr)
    ok = False
if extra:
    print(f"self-test FAIL: {len(extra)} unmarked line(s) flagged: {extra}", file=sys.stderr)
    ok = False
if hit_allowed:
    print(f"self-test FAIL: the allowed opener line was flagged: {hit_allowed}", file=sys.stderr)
    ok = False
if ok:
    print(f"no-raw-open self-test: ok ({len(expected)} marked lines all flagged, allowed opener not flagged)")
    sys.exit(0)
sys.exit(1)
PY
