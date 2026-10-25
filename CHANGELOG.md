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
  the allowed opener not flagged.

### Changed
- **Breaking:** `UrlAllowList::check` now returns `CheckedUrl` instead of
  `StrictUrl`. `CheckedUrl` derefs to `StrictUrl`, so the part accessors
  (`host()`, `path()`, `scheme()`, …) still work; only an explicit
  `let _: StrictUrl = list.check(..)?` binding needs to change. `allows()` and
  `parse_strict()` are unchanged.
