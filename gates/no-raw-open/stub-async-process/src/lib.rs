//! Stub of `async_process::Command`, named so clippy's disallowed-types
//! resolves the fixture's call sites to `async_process::Command`.
#![allow(unused_variables)]

pub struct Command;
impl Command {
    #[must_use]
    pub fn new(program: &str) -> Self {
        Command
    }
    pub fn arg(&mut self, a: &str) -> &mut Self {
        self
    }
}
