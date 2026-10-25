#!/usr/bin/env python3
"""no_opener_dep_check.py — a consumer's own crates must not directly depend on
a process/URL launcher, except the single opener wrapper.

Clippy's `disallowed-methods` / `disallowed-types` catch the call sites; this
catches the dependency a list can't enumerate: if a crate is a DIRECT dependency
of one of the consumer's own (workspace) crates, that crate could launch
something. We flag a direct dependency on any of:

    libc, nix, windows-sys, winapi, async-process, duct, open, opener, webbrowser
    tokio  (only when the `process` feature is enabled)

except for the opener wrapper crate(s) named with --opener. Transitive use is
fine (libc is a transitive dep of almost everything), so only DIRECT
dependencies of workspace members are checked.

Exit: 0 clean, 1 self-test failure, 2 a finding or nothing compared.

usage:
  no_opener_dep_check.py [--manifest PATH] [--opener NAME ...]
  no_opener_dep_check.py --self-test
"""
from __future__ import annotations

import json
import subprocess
import sys

BANNED = {
    "libc", "nix", "windows-sys", "winapi", "async-process", "duct",
    "open", "opener", "webbrowser",
}


def findings(metadata: dict, openers: set[str]) -> tuple[list[str], int]:
    """Return (messages, members_compared) for a cargo-metadata document."""
    members = set(metadata.get("workspace_members") or [])
    out: list[str] = []
    compared = 0
    for pkg in metadata.get("packages") or []:
        if pkg.get("id") not in members:
            continue
        name = pkg.get("name", "?")
        if name in openers:
            continue
        compared += 1
        for dep in pkg.get("dependencies") or []:
            # only normal (not dev/build) direct dependencies can ship a launcher
            if dep.get("kind") not in (None, "normal"):
                continue
            dname = dep.get("name", "")
            feats = dep.get("features") or []
            if dname in BANNED:
                out.append(f"{name}: direct dependency on `{dname}` (not the opener wrapper)")
            elif dname == "tokio" and ("process" in feats):
                out.append(f"{name}: direct dependency on `tokio` with the `process` feature")
    return out, compared


def run(manifest: str | None, openers: set[str]) -> int:
    cmd = ["cargo", "metadata", "--format-version", "1"]
    if manifest:
        cmd += ["--manifest-path", manifest]
    try:
        md = json.loads(subprocess.check_output(cmd, text=True))
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"no_opener_dep_check: cargo metadata failed: {e}", file=sys.stderr)
        return 2
    msgs, compared = findings(md, openers)
    if compared == 0:
        print("no_opener_dep_check: compared 0 workspace members", file=sys.stderr)
        return 2
    for m in msgs:
        print(m)
    print(f"no_opener_dep_check: {len(msgs)} finding(s) across {compared} member(s)")
    return 2 if msgs else 0


def self_test() -> int:
    def pkg(name, deps):
        return {"id": name, "name": name,
                "dependencies": [{"name": d, "kind": k, "features": f} for (d, k, f) in deps]}
    md = {
        "workspace_members": ["bad", "opener-wrap", "tokio-proc", "tokio-plain", "devonly"],
        "packages": [
            pkg("bad", [("libc", None, []), ("serde", None, [])]),            # 1 finding (libc)
            pkg("opener-wrap", [("open", None, [])]),                          # 0 (the opener)
            pkg("tokio-proc", [("tokio", None, ["rt", "process"])]),           # 1 finding (tokio+process)
            pkg("tokio-plain", [("tokio", None, ["rt"])]),                     # 0 (no process)
            pkg("devonly", [("open", "dev", [])]),                             # 0 (dev dep)
            pkg("not-a-member", [("libc", None, [])]),                         # ignored (not a member)
        ],
    }
    # not-a-member is not in workspace_members, so it is skipped
    msgs, compared = findings(md, openers={"opener-wrap"})
    ok = True
    if compared != 4:  # bad, tokio-proc, tokio-plain, devonly (opener-wrap excluded)
        ok = False
        print(f"self-test: compared {compared}, expected 4", file=sys.stderr)
    want = {
        "bad: direct dependency on `libc` (not the opener wrapper)",
        "tokio-proc: direct dependency on `tokio` with the `process` feature",
    }
    if set(msgs) != want:
        ok = False
        print(f"self-test: findings {sorted(msgs)} != expected {sorted(want)}", file=sys.stderr)
    if ok:
        print("no_opener_dep_check self-test: ok")
        return 0
    return 1


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return self_test()
    manifest = None
    openers: set[str] = set()
    i = 0
    while i < len(argv):
        if argv[i] == "--manifest":
            manifest = argv[i + 1]
            i += 2
        elif argv[i] == "--opener":
            openers.add(argv[i + 1])
            i += 2
        else:
            print(f"unknown arg: {argv[i]}", file=sys.stderr)
            return 2
    return run(manifest, openers)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
