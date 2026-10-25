# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `url::CheckedUrl`: a URL that has passed a `UrlAllowList`. Its constructor is
  private, so the only way to obtain one is `UrlAllowList::check` — holding a
  `CheckedUrl` is proof the URL was allowed. `CheckedUrl::as_str` renders the
  canonical URL from the already-validated parts (no re-parse, so no
  parser/serializer differential), and `CheckedUrl` derefs to `StrictUrl`.
- `url::UrlOpener` trait and `url::open_with(&opener, &CheckedUrl)`: an opener
  accepts only a `CheckedUrl`, so a URL cannot be opened without first passing a
  `UrlAllowList`. The crate stays `no_std` and opens nothing itself; the opener
  belongs to the consumer.
- A no-raw-open gate the crate ships for consumers: `gates/no-raw-open/clippy.toml`
  — `disallowed-types` for `std::process::Command`, `tokio::process::Command`
  and `async_process::Command` (type-level, so every constructor and builder is
  caught), and `disallowed-methods` for the `open` / `opener` / `webbrowser`
  openers, the `libc` / `nix` launch family (`system`, `popen`, `fork`, the
  `exec*` family, `posix_spawn*`) and the Windows ShellExecute / CreateProcess
  FFI. Clippy resolves paths, so renamed imports, split lines and aliased
  variables are caught; the one allowed opener carries
  `#[allow(clippy::disallowed_methods, clippy::disallowed_types)]`.
  `scripts/no_opener_dep_check.py` adds the dependency side via `cargo metadata`:
  a consumer crate must not directly depend on a launcher crate (`libc`, `nix`,
  `windows-sys`, `winapi`, `async-process`, `duct`, `open`, `opener`,
  `webbrowser`, or `tokio` with the `process` feature) except the opener
  wrapper; transitive use is fine. `scripts/no_raw_open_selftest.sh` lints a
  fixture of every bypass shape and requires the set of flagged lines to equal
  the marked lines exactly (so a false flag and an escape cannot cancel), with
  the allowed opener not flagged. `scripts/forbid_unsafe_check.py` closes the
  own-FFI escape (a crate declaring its own `extern "C" { fn system }`): every
  local package must carry `[lints.rust] unsafe_code = "forbid"` in its
  `Cargo.toml` (or inherit it through `[lints] workspace = true`), which bans
  FFI launchers at the compiler on every target (lib, bins, examples, tests).
  The check reads each manifest with a TOML parser — so a commented-out
  attribute, an inner `mod` attribute or a hidden bin target cannot fake it —
  and resolves workspace inheritance. It covers every local package, not only
  the workspace members (`cargo metadata` without `--no-deps`, every package
  whose source is null: members, excluded path deps, and path deps of path
  deps). Because the forbid lint does not fire for `unsafe` that arrives through
  an exported `macro_rules!`, the check also scans every local macro body for an
  `unsafe`/`extern` token on a comment/string-stripped copy of the source (so a
  comment or a string literal does not count) and bans local `proc-macro = true`
  crates. The only exception is the allow-listed opener package, trusted by
  review. Non-local (registry/git) dependencies are out of scope — the same
  trust boundary as any dependency. This crate carries
  `[lints.rust] unsafe_code = "forbid"` itself. The check takes its answers
  from cargo/rustc rather than re-deriving them: proc-macro crates from
  `cargo metadata` target kinds (covering the `proc_macro = true` alias), and
  the exact source-file set from rustc dep-info (covering `include!`d and
  `#[path]`d files, any extension, a directory named `target`); macro names may
  be raw identifiers. A committed fixture workspace
  (`gates/forbid-unsafe-fixture`) of every escape shape is run through the real
  check in CI and must flag all of them and nothing else. The gate's frozen
  threat model is stated in the `forbid_unsafe_check.py` module doc.

### Changed
- **Breaking:** `UrlAllowList::check` now returns `CheckedUrl` instead of
  `StrictUrl`. `CheckedUrl` derefs to `StrictUrl`, so the part accessors
  (`host()`, `path()`, `scheme()`, …) still work; only an explicit
  `let _: StrictUrl = list.check(..)?` binding needs to change. `allows()` and
  `parse_strict()` are unchanged.
