#!/usr/bin/env python3
"""forbid_unsafe_check.py — close the own-FFI escape from the no-raw-open gate.

A crate can declare its own launcher and call it under `unsafe`:

    extern "C" { fn system(cmd: *const u8) -> i32; }
    unsafe { system(..); }           // path is crate::system, no libc dep

No name list catches that, and matching `#![forbid(unsafe_code)]` in the source
is not enough: a commented-out attribute still matches the text, an inner
attribute inside a `mod` scopes only that module, and a crate with both a lib
and a bin hides the call in the target whose root is not read.

So we do not read the source at all. Cargo's lint table is the enforcement
point: `[lints.rust] unsafe_code = "forbid"` in a package's Cargo.toml applies
to EVERY target of the package (lib, bins, examples, tests), cannot be shadowed
by a module, and a comment cannot fake it. This check parses each workspace
package's manifest (and the workspace root) with tomllib — structured, so
comments and strings do not match — resolves `[lints] workspace = true`
inheritance, and requires the effective level to be `forbid` for every package
except the allow-listed opener.

Allow-list file (default gates/no-raw-open/unsafe-allow.toml):
    [[allow]]
    name = "my-opener"
    reason = "the single opener wrapper; performs the one real launch"
An allow-listed package is trusted by review (it is the one place a launch is
intended); the check does not try to prove it stays unsafe-free.

Exit: 0 clean, 1 self-test failure, 2 a finding or nothing compared.

usage:
  forbid_unsafe_check.py [--manifest PATH] [--allow-file PATH]
  forbid_unsafe_check.py --self-test
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _level(value: object) -> str | None:
    """Normalize a cargo lint value to its level string.

    `unsafe_code = "forbid"` -> "forbid";
    `unsafe_code = { level = "forbid", priority = -1 }` -> "forbid".
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        lvl = value.get("level")
        return lvl if isinstance(lvl, str) else None
    return None


def effective_unsafe_level(pkg_lints: dict, ws_lints: dict) -> str | None:
    """The effective `rust.unsafe_code` level for a package, or None if unset.

    `[lints] workspace = true` inherits `[workspace.lints]` wholesale (cargo
    forbids mixing `workspace = true` with other lint entries), so we take the
    workspace table in that case and the package's own table otherwise.
    """
    source = ws_lints if pkg_lints.get("workspace") is True else pkg_lints
    rust = source.get("rust") if isinstance(source, dict) else None
    if not isinstance(rust, dict):
        return None
    return _level(rust.get("unsafe_code"))


def check(packages: list[dict], allow: dict[str, str]) -> tuple[list[str], int]:
    """packages: [{name, pkg_lints, ws_lints}]; allow: name->reason.

    An allow-listed package is trusted by review and skipped. Every other
    package must resolve to `unsafe_code = "forbid"`; missing or a weaker level
    (deny / warn / allow) is a finding.
    """
    findings: list[str] = []
    compared = 0
    for p in packages:
        compared += 1
        name = p["name"]
        if name in allow:
            continue
        lvl = effective_unsafe_level(p.get("pkg_lints", {}), p.get("ws_lints", {}))
        if lvl == "forbid":
            continue
        shown = lvl if lvl is not None else "unset"
        findings.append(
            f"{name}: effective [lints.rust] unsafe_code is `{shown}`, "
            f"must be `forbid` (and the package is not the allow-listed opener)"
        )
    return findings, compared


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


def run(manifest: str | None, allow_file: Path) -> int:
    cmd = ["cargo", "metadata", "--format-version", "1", "--no-deps"]
    if manifest:
        cmd += ["--manifest-path", manifest]
    try:
        md = json.loads(subprocess.check_output(cmd, text=True))
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"forbid_unsafe_check: cargo metadata failed: {e}", file=sys.stderr)
        return 2

    ws_root = md.get("workspace_root")
    ws_lints: dict = {}
    if ws_root:
        try:
            ws_lints = _read_toml(Path(ws_root) / "Cargo.toml").get("workspace", {}).get("lints", {})
        except Exception as e:  # noqa: BLE001
            print(f"forbid_unsafe_check: cannot read workspace root manifest: {e}", file=sys.stderr)
            return 2

    allow = _read_allow(allow_file)
    packages = []
    for pkg in md.get("packages", []):
        try:
            pkg_lints = _read_toml(Path(pkg["manifest_path"])).get("lints", {})
        except Exception as e:  # noqa: BLE001
            print(f"forbid_unsafe_check: cannot read {pkg['manifest_path']}: {e}", file=sys.stderr)
            return 2
        packages.append({"name": pkg["name"], "pkg_lints": pkg_lints, "ws_lints": ws_lints})

    findings, compared = check(packages, allow)
    if compared == 0:
        print("forbid_unsafe_check: compared 0 packages", file=sys.stderr)
        return 2
    for f in findings:
        print(f)
    print(f"forbid_unsafe_check: {len(findings)} finding(s) across {compared} package(s)")
    return 2 if findings else 0


def self_test() -> int:
    # The 3 source-shapes 9e found all reduce to "no manifest forbid" here,
    # because this check reads the manifest, not the source:
    #   - a commented `// #![forbid]`     -> no [lints] -> unset -> finding
    #   - an inner `mod m { #![forbid] }` -> no [lints] -> unset -> finding
    #   - lib carries it, bin does not    -> the manifest covers both -> no escape
    packages = [
        {"name": "ok-pkg", "pkg_lints": {"rust": {"unsafe_code": "forbid"}}, "ws_lints": {}},
        {"name": "ok-pkg-table", "pkg_lints": {"rust": {"unsafe_code": {"level": "forbid", "priority": -1}}}, "ws_lints": {}},
        {"name": "ok-workspace", "pkg_lints": {"workspace": True}, "ws_lints": {"rust": {"unsafe_code": "forbid"}}},
        {"name": "unset", "pkg_lints": {}, "ws_lints": {}},  # finding (commented / nested-mod shape)
        {"name": "too-weak", "pkg_lints": {"rust": {"unsafe_code": "deny"}}, "ws_lints": {}},  # finding
        {"name": "ws-missing", "pkg_lints": {"workspace": True}, "ws_lints": {}},  # finding: workspace=true, ws lacks it
        {"name": "the-opener", "pkg_lints": {}, "ws_lints": {}},  # allow-listed, trusted by review -> skipped
    ]
    allow = {"the-opener": "the opener wrapper"}
    findings, compared = check(packages, allow)
    want = {
        "unset: effective [lints.rust] unsafe_code is `unset`, must be `forbid` (and the package is not the allow-listed opener)",
        "too-weak: effective [lints.rust] unsafe_code is `deny`, must be `forbid` (and the package is not the allow-listed opener)",
        "ws-missing: effective [lints.rust] unsafe_code is `unset`, must be `forbid` (and the package is not the allow-listed opener)",
    }
    ok = True
    if compared != 7:
        ok = False
        print(f"self-test: compared {compared}, expected 7", file=sys.stderr)
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
