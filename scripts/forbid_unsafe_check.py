#!/usr/bin/env python3
"""forbid_unsafe_check.py — close the own-FFI escape from the no-raw-open gate.

A crate can declare its own launcher and call it under `unsafe`:

    extern "C" { fn system(cmd: *const u8) -> i32; }
    unsafe { system(..); }           // path is crate::system, no libc dep

No name list catches that. Cargo's lint table is the enforcement point:
`[lints.rust] unsafe_code = "forbid"` in a package's Cargo.toml applies to EVERY
target of the package (lib, bins, examples, tests) at the compiler, cannot be
shadowed by a module, and a comment cannot fake it. This check requires that
level on every LOCAL package and adds two scans for the paths the compiler lint
does not cover on its own:

  * Every local package is checked, not just the workspace members: we read
    `cargo metadata` WITHOUT `--no-deps` and take every package whose `source`
    is null (members, excluded path deps, and path deps of path deps). A path
    dep sitting in `[workspace] exclude` is still your own code.

  * `unsafe_code = "forbid"` does not fire for an `unsafe` block that arrives
    through an exported `macro_rules!` (rustc does not lint unsafe in spans from
    an external macro). So we scan every local `macro_rules!` body for an
    `unsafe` or `extern` token — on a comment/string-stripped copy of the source
    (the scanner's own tokenizer), so a comment or a string literal does not
    count — and we ban local `proc-macro = true` crates outside the allow-list
    (scanning their generated output is impractical).

Scope boundary: a NON-local dependency (registry or git) that calls a launcher
inside a safe `fn`, or exports an `unsafe` macro, is the same trust boundary as
any dependency — out of scope here; vet dependencies separately. This gate
covers your own (local) code.

Allow-list file (default gates/no-raw-open/unsafe-allow.toml):
    [[allow]]
    name = "my-opener"
    reason = "the single opener wrapper; performs the one real launch"
An allow-listed package is trusted by review (it is the one place a launch is
intended); it is skipped by all three checks.

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

_MACRO_UNSAFE = re.compile(r"\b(unsafe|extern)\b")


# ---- manifest lint ---------------------------------------------------------

def _level(value: object) -> str | None:
    """Normalize a cargo lint value to its level string."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        lvl = value.get("level")
        return lvl if isinstance(lvl, str) else None
    return None


def effective_unsafe_level(pkg_lints: dict, ws_lints: dict) -> str | None:
    """Effective `rust.unsafe_code` level for a package, or None if unset.

    `[lints] workspace = true` inherits `[workspace.lints]` wholesale (cargo
    forbids mixing it with other lint entries), so take the workspace table in
    that case and the package's own table otherwise.
    """
    source = ws_lints if pkg_lints.get("workspace") is True else pkg_lints
    rust = source.get("rust") if isinstance(source, dict) else None
    if not isinstance(rust, dict):
        return None
    return _level(rust.get("unsafe_code"))


# ---- Rust-aware stripping + macro_rules scan -------------------------------

def strip_rust(text: str) -> str:
    """Replace comments and string/char literals with equal-length blanks.

    Offsets and brace structure OUTSIDE literals are preserved, so a `{`, a
    keyword or a quote inside a comment or a string cannot affect later
    brace-matching or token scanning. This is the scanner's own tokenizer: it is
    not a regex over the raw text.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        # line comment
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i)); i = j; continue
        # block comment (nested)
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1; j = i + 2
            while j < n and depth:
                if text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                    depth += 1; j += 2; continue
                if text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                    depth -= 1; j += 2; continue
                j += 1
            out.append(" " * (j - i)); i = j; continue
        # raw string: (b)r #* "
        if c in "br":
            m = re.match(r"b?r(#*)\"", text[i:])
            if m:
                close = '"' + m.group(1)
                j = text.find(close, i + m.end())
                j = n if j == -1 else j + len(close)
                out.append(" " * (j - i)); i = j; continue
        # normal / byte string
        if c == '"' or (c == "b" and i + 1 < n and text[i + 1] == '"'):
            j = i + (2 if c == "b" else 1)
            while j < n:
                if text[j] == "\\":
                    j += 2; continue
                if text[j] == '"':
                    j += 1; break
                j += 1
            out.append(" " * (j - i)); i = j; continue
        # char / byte-char literal (not a lifetime): 'x' 'b' '\n' b'x'
        if c == "'" or (c == "b" and i + 1 < n and text[i + 1] == "'"):
            q = i + (1 if c == "b" else 0)      # index of the opening quote
            k = q + 1
            if k < n and text[k] == "\\":       # escaped char
                j = text.find("'", k)
                if j != -1 and j - k <= 4:
                    out.append(" " * (j + 1 - i)); i = j + 1; continue
            elif k + 1 < n and text[k + 1] == "'":   # simple 'x'
                out.append(" " * (k + 2 - i)); i = k + 2; continue
            # otherwise a lifetime tick — emit as-is
            out.append(c); i += 1; continue
        out.append(c); i += 1
    return "".join(out)


def macro_rules_bodies(stripped: str) -> list[str]:
    """Bodies of every `macro_rules!` in already-stripped source."""
    bodies: list[str] = []
    for m in re.finditer(r"\bmacro_rules\s*!\s*\w+\s*", stripped):
        k = m.end()
        while k < len(stripped) and stripped[k] in " \t\r\n":
            k += 1
        if k >= len(stripped):
            continue
        opener = stripped[k]
        closer = {"{": "}", "(": ")", "[": "]"}.get(opener)
        if closer is None:
            continue
        depth = 0; j = k
        while j < len(stripped):
            ch = stripped[j]
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    bodies.append(stripped[k + 1:j]); break
            j += 1
    return bodies


def macro_has_unsafe(rs_texts: list[str]) -> bool:
    for t in rs_texts:
        for body in macro_rules_bodies(strip_rust(t)):
            if _MACRO_UNSAFE.search(body):
                return True
    return False


# ---- the check -------------------------------------------------------------

def check(packages: list[dict], allow: dict[str, str]) -> tuple[list[str], int]:
    """packages: [{name, pkg_lints, ws_lints, rs_texts, is_proc_macro}]."""
    findings: list[str] = []
    compared = 0
    for p in packages:
        compared += 1
        name = p["name"]
        if name in allow:
            continue
        lvl = effective_unsafe_level(p.get("pkg_lints", {}), p.get("ws_lints", {}))
        if lvl != "forbid":
            shown = lvl if lvl is not None else "unset"
            findings.append(
                f"{name}: effective [lints.rust] unsafe_code is `{shown}`, "
                f"must be `forbid` (and the package is not the allow-listed opener)"
            )
        if p.get("is_proc_macro"):
            findings.append(
                f"{name}: local proc-macro crate must be in the opener allow-list "
                f"(its generated code is not scannable)"
            )
        if macro_has_unsafe(p.get("rs_texts", [])):
            findings.append(
                f"{name}: a local macro_rules! body contains an `unsafe`/`extern` token "
                f"(unsafe through an exported macro is not caught by the forbid lint)"
            )
    return findings, compared


# ---- gathering -------------------------------------------------------------

def _read_toml(path: Path) -> dict:
    import tomllib
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _read_allow(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        data = _read_toml(path)
    except Exception as e:  # noqa: BLE001
        print(f"forbid_unsafe_check: cannot read {path}: {e}", file=sys.stderr)
        return {}
    return {e["name"]: e.get("reason", "") for e in data.get("allow", []) if "name" in e}


def _workspace_lints(start: Path) -> dict:
    """Walk up from a package dir to the manifest that owns `[workspace]`."""
    d = start
    while True:
        mani = d / "Cargo.toml"
        if mani.exists():
            try:
                t = _read_toml(mani)
            except Exception:  # noqa: BLE001
                t = {}
            if "workspace" in t:
                return t.get("workspace", {}).get("lints", {})
        if d.parent == d:
            return {}
        d = d.parent


def _is_proc_macro(manifest: dict) -> bool:
    return manifest.get("lib", {}).get("proc-macro") is True


def _crate_rs_texts(crate_dir: Path) -> list[str]:
    texts = []
    for p in crate_dir.rglob("*.rs"):
        if "/target/" in str(p).replace("\\", "/"):
            continue
        texts.append(p.read_text(encoding="utf-8", errors="replace"))
    return texts


def run(manifest: str | None, allow_file: Path) -> int:
    # WITHOUT --no-deps: resolve the whole graph so excluded path deps and path
    # deps of path deps are present; we then keep only the local ones.
    cmd = ["cargo", "metadata", "--format-version", "1"]
    if manifest:
        cmd += ["--manifest-path", manifest]
    try:
        md = json.loads(subprocess.check_output(cmd, text=True))
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"forbid_unsafe_check: cargo metadata failed: {e}", file=sys.stderr)
        return 2

    allow = _read_allow(allow_file)
    packages = []
    for pkg in md.get("packages", []):
        if pkg.get("source") is not None:   # registry / git = out of scope
            continue
        mani_path = Path(pkg["manifest_path"])
        try:
            mani = _read_toml(mani_path)
        except Exception as e:  # noqa: BLE001
            print(f"forbid_unsafe_check: cannot read {mani_path}: {e}", file=sys.stderr)
            return 2
        pkg_lints = mani.get("lints", {})
        ws_lints = _workspace_lints(mani_path.parent) if pkg_lints.get("workspace") is True else {}
        packages.append({
            "name": pkg["name"],
            "pkg_lints": pkg_lints,
            "ws_lints": ws_lints,
            "is_proc_macro": _is_proc_macro(mani),
            "rs_texts": _crate_rs_texts(mani_path.parent),
        })

    findings, compared = check(packages, allow)
    if compared == 0:
        print("forbid_unsafe_check: compared 0 local packages", file=sys.stderr)
        return 2
    for f in findings:
        print(f)
    print(f"forbid_unsafe_check: {len(findings)} finding(s) across {compared} local package(s)")
    return 2 if findings else 0


# ---- self-test -------------------------------------------------------------

_MAC_UNSAFE = (
    '#[macro_export] macro_rules! launch { ($c:expr) => {{ '
    'extern "C" { fn system(c: *const u8) -> i32; } unsafe { system($c) } }} }'
)
_MAC_BENIGN = (
    '// macro_rules! commented { () => { unsafe {} } }\n'
    'macro_rules! benign { () => { let s = "unsafe"; let e = "extern"; } }'
)


def self_test() -> int:
    packages = [
        # the 3 earlier shapes reduce to "no manifest forbid = finding"
        {"name": "ok-pkg", "pkg_lints": {"rust": {"unsafe_code": "forbid"}}, "ws_lints": {}, "rs_texts": [], "is_proc_macro": False},
        {"name": "ok-table", "pkg_lints": {"rust": {"unsafe_code": {"level": "forbid"}}}, "ws_lints": {}, "rs_texts": [], "is_proc_macro": False},
        {"name": "ok-workspace", "pkg_lints": {"workspace": True}, "ws_lints": {"rust": {"unsafe_code": "forbid"}}, "rs_texts": [], "is_proc_macro": False},
        {"name": "unset", "pkg_lints": {}, "ws_lints": {}, "rs_texts": [], "is_proc_macro": False},  # finding
        {"name": "too-weak", "pkg_lints": {"rust": {"unsafe_code": "deny"}}, "ws_lints": {}, "rs_texts": [], "is_proc_macro": False},  # finding
        {"name": "ws-missing", "pkg_lints": {"workspace": True}, "ws_lints": {}, "rs_texts": [], "is_proc_macro": False},  # finding
        # r6 (2): excluded path dep with no lint -> manifest finding
        {"name": "outside", "pkg_lints": {}, "ws_lints": {}, "rs_texts": ['pub fn run() { /* calls its own system */ }'], "is_proc_macro": False},  # finding (unset)
        # r6 (1a): forbid manifest BUT an exported macro smuggles unsafe -> macro finding
        {"name": "mac", "pkg_lints": {"rust": {"unsafe_code": "forbid"}}, "ws_lints": {}, "rs_texts": [_MAC_UNSAFE], "is_proc_macro": False},  # finding (macro)
        # r6 (1a control): unsafe only in a comment and a string -> NO finding
        {"name": "benign", "pkg_lints": {"rust": {"unsafe_code": "forbid"}}, "ws_lints": {}, "rs_texts": [_MAC_BENIGN], "is_proc_macro": False},
        # r6 (1b): local proc-macro crate -> finding
        {"name": "pm", "pkg_lints": {"rust": {"unsafe_code": "forbid"}}, "ws_lints": {}, "rs_texts": [], "is_proc_macro": True},  # finding (proc-macro)
        # allow-listed opener with an unsafe macro -> skipped entirely
        {"name": "the-opener", "pkg_lints": {}, "ws_lints": {}, "rs_texts": [_MAC_UNSAFE], "is_proc_macro": True},
    ]
    allow = {"the-opener": "the opener wrapper"}
    findings, compared = check(packages, allow)
    want = {
        "unset: effective [lints.rust] unsafe_code is `unset`, must be `forbid` (and the package is not the allow-listed opener)",
        "too-weak: effective [lints.rust] unsafe_code is `deny`, must be `forbid` (and the package is not the allow-listed opener)",
        "ws-missing: effective [lints.rust] unsafe_code is `unset`, must be `forbid` (and the package is not the allow-listed opener)",
        "outside: effective [lints.rust] unsafe_code is `unset`, must be `forbid` (and the package is not the allow-listed opener)",
        "mac: a local macro_rules! body contains an `unsafe`/`extern` token (unsafe through an exported macro is not caught by the forbid lint)",
        "pm: local proc-macro crate must be in the opener allow-list (its generated code is not scannable)",
    }
    ok = True
    if compared != 11:
        ok = False
        print(f"self-test: compared {compared}, expected 11", file=sys.stderr)
    if set(findings) != want:
        ok = False
        extra = sorted(set(findings) - want)
        missing = sorted(want - set(findings))
        print(f"self-test: extra={extra} missing={missing}", file=sys.stderr)
    # the stripper must neutralize the commented/quoted unsafe exactly
    if macro_has_unsafe([_MAC_BENIGN]):
        ok = False
        print("self-test: stripper let a comment/string `unsafe` through", file=sys.stderr)
    if not macro_has_unsafe([_MAC_UNSAFE]):
        ok = False
        print("self-test: stripper missed a real macro `unsafe`", file=sys.stderr)
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
