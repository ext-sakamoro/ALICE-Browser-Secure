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
- `scripts/no_raw_open_check.py`: a gate (with a self-test; fails when it
  compares nothing) that flags a raw URL open (`open::that`, a shelled-out
  `open` / `xdg-open` / `start`, `webbrowser::open`) outside an `open_with`
  path, so the single legitimate raw open lives inside the `UrlOpener` impl
  (marked `alice-checked-open`). Consumers pin it by revision with a SHA-256
  check.

### Changed
- **Breaking:** `UrlAllowList::check` now returns `CheckedUrl` instead of
  `StrictUrl`. `CheckedUrl` derefs to `StrictUrl`, so the part accessors
  (`host()`, `path()`, `scheme()`, …) still work; only an explicit
  `let _: StrictUrl = list.check(..)?` binding needs to change. `allows()` and
  `parse_strict()` are unchanged.
