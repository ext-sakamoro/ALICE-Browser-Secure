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
  (`disallowed-methods` for `std::process::Command::new`, the `open` / `opener`
  / `webbrowser` entry points, and the `libc` / `windows-sys` process-launch
  FFI) and `gates/no-raw-open/deny.toml` (cargo-deny `bans` on those crates
  except the consumer's single opener crate). Clippy resolves paths, so renamed
  imports, split lines, aliased variables and the FFI shapes are all caught; the
  one allowed opener carries `#[allow(clippy::disallowed_methods)]`.
  `scripts/no_raw_open_selftest.sh` lints a fixture of every bypass shape and
  requires clippy's finding count to equal the marked lines (fails on 0).

### Changed
- **Breaking:** `UrlAllowList::check` now returns `CheckedUrl` instead of
  `StrictUrl`. `CheckedUrl` derefs to `StrictUrl`, so the part accessors
  (`host()`, `path()`, `scheme()`, …) still work; only an explicit
  `let _: StrictUrl = list.check(..)?` binding needs to change. `allows()` and
  `parse_strict()` are unchanged.
