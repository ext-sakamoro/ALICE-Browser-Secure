//! Stub of `tokio::process::Command`, named so clippy's disallowed-types
//! resolves the fixture's call sites to `tokio::process::Command`.
#![allow(unused_variables)]

pub mod process {
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
}
