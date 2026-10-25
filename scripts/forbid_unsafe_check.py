#!/usr/bin/env python3
"""forbid_unsafe_check.py — close the own-FFI escape from the no-raw-open gate.

A crate can declare its own launcher and call it under `unsafe`:

    extern "C" { fn system(cmd: *const u8) -> i32; }
    unsafe { system(..); }           // path is crate::system, no libc dep

No name list can catch that. But every FFI call needs `unsafe`, so we require
each of a consumer's own (workspace) crate roots to carry
`#![forbid(unsafe_code)]`. Crates with a genuine FFI need are listed in an
allow-list (TOML, each with a reason) — the opener wrapper and any such crate —
and those listed crates get a second check: no `extern` block may declare a
process-launch symbol.

Allow-list file (default gates/no-raw-open/unsafe-allow.toml):
    [[allow]]
    name = "my-opener"
    reason = "the single opener wrapper; performs the one real launch"

Exit: 0 clean, 1 self-test failure, 2 a finding or nothing compared.

usage:
  forbid_unsafe_check.py [--manifest PATH] [--allow-file PATH]
  forbid_unsafe_check.py --self-test
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

LAUNCH = [
    "system", "popen", "fork",
    "execv", "execvp", "execve", "execvpe", "execl", "execlp", "execle",
    "execveat", "fexecve",
    "posix_spawn", "posix_spawnp",
    "CreateProcessW", "CreateProcessA",
    "ShellExecuteW", "ShellExecuteA", "ShellExecuteExW",
]
_LAUNCH_FN = re.compile(r"\bfn\s+(" + "|".join(LAUNCH) + r")\b")
_FORBID = re.compile(r"#!\s*\[\s*forbid\s*\(([^)]*)\)\s*\]")
_EXTERN_OPEN = re.compile(r'\bextern\b[^\{;]*\{')


def has_forbid_unsafe(root_text: str) -> bool:
    for m in _FORBID.finditer(root_text):
        items = [i.strip() for i in m.group(1).split(",")]
        if "unsafe_code" in items:
            return True
    return False


def extern_launchers(text: str) -> list[str]:
    """Launch symbols declared inside any `extern` block in `text`."""
    out: list[str] = []
    depth = 0
    in_extern = False
    i = 0
    n = len(text)
    # walk char by char, tracking brace depth once an `extern … {` opens
    while i < n:
        if not in_extern:
            m = _EXTERN_OPEN.search(text, i)
            if not m:
                break
            in_extern = True
            depth = 1
            i = m.end()
            block_start = i
            continue
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                block = text[block_start:i]
                out += _LAUNCH_FN.findall(block)
                in_extern = False
        i += 1
    return out


def check(crates: list[dict], allow: dict[str, str]) -> tuple[list[str], int]:
    """crates: [{name, root_text, source_texts:[...]}]; allow: name->reason."""
    findings: list[str] = []
    compared = 0
    for c in crates:
        compared += 1
        name = c["name"]
        if name in allow:
            seen: list[str] = []
            for t in c.get("source_texts", [c.get("root_text", "")]):
                seen += extern_launchers(t)
            for sym in sorted(set(seen)):
                findings.append(f"{name}: allow-listed, but declares launcher `{sym}` in an extern block")
        else:
            if not has_forbid_unsafe(c.get("root_text", "")):
                findings.append(f"{name}: crate root lacks #![forbid(unsafe_code)] (and is not in the opener allow-list)")
    return findings, compared


def _read_allow(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        print(f"forbid_unsafe_check: cannot read {path}: {e}", file=sys.stderr)
        return {}
    return {e["name"]: e.get("reason", "") for e in data.get("allow", []) if "name" in e}


def run(manifest: str | None, allow_file: Path) -> int:
    cmd = ["cargo", "metadata", "--format-version", "1", "--no-deps"]
    if manifest:
        cmd += ["--manifest-path", manifest]
    try:
        md = json.loads(subprocess.check_output(cmd, text=True))
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"forbid_unsafe_check: cargo metadata failed: {e}", file=sys.stderr)
        return 2
    allow = _read_allow(allow_file)
    crates = []
    for pkg in md.get("packages", []):
        roots = [Path(t["src_path"]) for t in pkg.get("targets", [])
                 if set(t.get("kind", [])) & {"lib", "bin", "cdylib", "staticlib", "rlib"}]
        if not roots:
            continue
        root_text = roots[0].read_text(encoding="utf-8", errors="replace")
        srcs = [root_text]
        if pkg["name"] in allow:  # second check needs the whole crate
            crate_dir = roots[0].parent
            srcs = [p.read_text(encoding="utf-8", errors="replace") for p in crate_dir.rglob("*.rs")]
        crates.append({"name": pkg["name"], "root_text": root_text, "source_texts": srcs})
    findings, compared = check(crates, allow)
    if compared == 0:
        print("forbid_unsafe_check: compared 0 crates", file=sys.stderr)
        return 2
    for f in findings:
        print(f)
    print(f"forbid_unsafe_check: {len(findings)} finding(s) across {compared} crate(s)")
    return 2 if findings else 0


def self_test() -> int:
    crates = [
        {"name": "ok-crate", "root_text": "#![no_std]\n#![forbid(unsafe_code)]\n", "source_texts": []},
        {"name": "no-forbid", "root_text": "#![no_std]\n", "source_texts": []},  # finding
        {"name": "own-ffi", "root_text": "pub fn go(){}\n",                      # finding (no forbid)
         "source_texts": ['extern "C" { fn system(c: *const u8) -> i32; }\nfn go(){ unsafe { system(core::ptr::null()); } }\n']},
        {"name": "the-opener", "root_text": "pub fn open(){}\n",                 # allow-listed, clean extern
         "source_texts": ['extern "C" { fn write(fd: i32); }\n']},
        {"name": "bad-opener", "root_text": "pub fn open(){}\n",                 # allow-listed BUT declares a launcher
         "source_texts": ['extern "C" { fn popen(c: *const u8, m: *const u8) -> *mut u8; }\n']},
    ]
    allow = {"the-opener": "the opener wrapper", "bad-opener": "claims an FFI need"}
    findings, compared = check(crates, allow)
    want = {
        "no-forbid: crate root lacks #![forbid(unsafe_code)] (and is not in the opener allow-list)",
        "own-ffi: crate root lacks #![forbid(unsafe_code)] (and is not in the opener allow-list)",
        "bad-opener: allow-listed, but declares launcher `popen` in an extern block",
    }
    ok = True
    if compared != 5:
        ok = False
        print(f"self-test: compared {compared}, expected 5", file=sys.stderr)
    if set(findings) != want:
        ok = False
        print(f"self-test: findings {sorted(findings)} != expected {sorted(want)}", file=sys.stderr)
    if ok:
        print("forbid_unsafe_check self-test: ok")
        return 0
    return 1


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return self_test()
    manifest = None
    allow_file = Path("gates/no-raw-open/unsafe-allow.toml")
    i = 0
    while i < len(argv):
        if argv[i] == "--manifest":
            manifest = argv[i + 1]; i += 2
        elif argv[i] == "--allow-file":
            allow_file = Path(argv[i + 1]); i += 2
        else:
            print(f"unknown arg: {argv[i]}", file=sys.stderr); return 2
    return run(manifest, allow_file)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
