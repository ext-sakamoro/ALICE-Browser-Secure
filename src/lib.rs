//! ALICE-Browser-Secure — Secure browsing engine
//!
//! CSP生成、XSS検出、URL検証、HTML sanitization
//!
//! # Module 構成
//! | Module | 内容 |
//! |--------|------|
//! | [`csp`] | Content Security Policy generation |
//! | [`xss`] | XSS detection |
//! | [`sanitizer`] | HTML sanitization |
//! | [`url`] | URL validation |
//! | [`csrf`] | CSRF token |
//! | [`error`] | Error types |
//! | [`prelude`] | 主要 API 一括 re-export |

#![no_std]

extern crate alloc;

pub mod csp;
pub mod csrf;
pub mod error;
pub mod prelude;
pub mod sanitizer;
pub mod url;
pub mod xss;

#[cfg(test)]
mod integration_tests;

// Backward-compatible re-exports
pub use crate::csp::*;
pub use crate::csrf::*;
pub use crate::error::*;
pub use crate::sanitizer::*;
pub use crate::url::*;
pub use crate::xss::*;
