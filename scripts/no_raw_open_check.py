#!/usr/bin/env python3
"""no_raw_open_check.py — forbid opening a URL without a CheckedUrl.

A consumer of alice-browser-secure must route every browser / shell "open" of a
URL through `open_with(&opener, &CheckedUrl)` (or a UrlOpener impl that receives
a &CheckedUrl). A raw opener taking a &str — std's `open::that`, a shelled-out
`open` / `xdg-open` / `start` / `cmd /c start`, or `webbrowser::open` — bypasses
the type gate, so this check flags each such call site.

The one legitimate raw open is inside the UrlOpener impl, which already holds a
&CheckedUrl; mark that single line (or the line above it) with the exact comment
token `alice-checked-open` to allow it.

Consumers pin this script by revision and verify its SHA-256 (the same pattern
as the public-text check), so the gate they run is the one shipped here.

Exit codes: 0 clean, 1 self-test failure, 2 a finding or nothing compared.

usage:
  no_raw_open_check.py [PATH ...]   # scan .rs files under each PATH (default: .)
  no_raw_open_check.py --self-test  # run the built-in fixtures
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ALLOW_TOKEN = "alice-checked-open"

# raw openers that take a string rather than a CheckedUrl
PATTERNS = [
    re.compile(r"\bopen::that(?:_in_background)?\s*\("),
    re.compile(r'Command::new\(\s*"(?:open|xdg-open|start|cmd)"'),
    re.compile(r"\bwebbrowser::\w*open"),
]


def findings_in_text(text: str) -> list[tuple[int, str]]:
    """Return (line_no, line) for each raw-open not allowed by the token.

    A line is allowed when it, or the line immediately above it, carries the
    ALLOW_TOKEN comment.
    """
    lines = text.splitlines()
    out: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        if not any(p.search(line) for p in PATTERNS):
            continue
        above = lines[i - 1] if i > 0 else ""
        if ALLOW_TOKEN in line or ALLOW_TOKEN in above:
            continue
        out.append((i + 1, line.strip()))
    return out


def scan(roots: list[Path]) -> tuple[list[str], int]:
    """Scan .rs files under roots; return (finding_messages, files_compared)."""
    findings: list[str] = []
    compared = 0
    for root in roots:
        files = [root] if root.is_file() else sorted(root.rglob("*.rs"))
        for f in files:
            if f.suffix != ".rs":
                continue
            # the shipped script lives under scripts/; skip nothing by path here —
            # the consumer decides the roots it passes
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                findings.append(f"{f}: cannot read: {e}")
                continue
            compared += 1
            for ln, line in findings_in_text(text):
                findings.append(f"{f}:{ln}: raw URL open without a CheckedUrl: {line}")
    return findings, compared


def self_test() -> int:
    raw = 'fn go(u: &str) { let _ = open::that(u); }\n'
    shell = 'Command::new("xdg-open").arg(u).status()\n'
    allowed_inline = '    let _ = open::that(c.as_str()); // alice-checked-open: inside UrlOpener\n'
    allowed_above = "    // alice-checked-open: inside UrlOpener\n    open::that(c.as_str())?;\n"
    clean = "fn open(&self, u: &CheckedUrl) { open_with(self, u) }\n"

    cases = [
        ("raw.rs", raw, 1),
        ("shell.rs", shell, 1),
        ("allowed_inline.rs", allowed_inline, 0),
        ("allowed_above.rs", allowed_above, 0),
        ("clean.rs", clean, 0),
    ]
    ok = True
    with tempfile.TemporaryDirectory() as d:
        dp = Path(d)
        for name, text, want in cases:
            (dp / name).write_text(text, encoding="utf-8")
            got = len(findings_in_text(text))
            if got != want:
                ok = False
                print(f"self-test {name}: expected {want} finding(s), got {got}", file=sys.stderr)
        findings, compared = scan([dp])
        if compared != len(cases):
            ok = False
            print(f"self-test: compared {compared}, expected {len(cases)}", file=sys.stderr)
        # the two bad fixtures must be the only findings
        if len(findings) != 2:
            ok = False
            print(f"self-test: expected 2 scan findings, got {len(findings)}: {findings}", file=sys.stderr)
    if ok:
        print("no_raw_open_check self-test: ok")
        return 0
    return 1


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return self_test()
    roots = [Path(a) for a in argv] if argv else [Path(".")]
    findings, compared = scan(roots)
    if compared == 0:
        print("no_raw_open_check: compared 0 files (nothing scanned)", file=sys.stderr)
        return 2
    for f in findings:
        print(f)
    print(f"no_raw_open_check: {len(findings)} finding(s) in {compared} file(s)")
    return 2 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
