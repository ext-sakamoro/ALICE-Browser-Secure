//! Stub of the `open` crate's entry points, named so clippy resolves the
//! fixture's call sites to `open::*` (no real download). Bodies do nothing.
#![allow(clippy::must_use_candidate, unused_variables)]

pub fn that(path: &str) {}
pub fn that_detached(path: &str) {}
pub fn that_in_background(path: &str) {}
pub fn with(path: &str, app: &str) {}
pub fn with_detached(path: &str, app: &str) {}
