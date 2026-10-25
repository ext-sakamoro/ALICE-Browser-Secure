//! Stub of `nix::unistd` exec/fork entry points, named so clippy resolves the
//! fixture's call sites to `nix::unistd::*`.
#![allow(unused_variables)]

pub mod unistd {
    pub fn execv(path: &str, argv: &[&str]) {}
    pub fn execve(path: &str, argv: &[&str], envp: &[&str]) {}
    pub fn execvp(file: &str, argv: &[&str]) {}
    pub fn execvpe(file: &str, argv: &[&str], envp: &[&str]) {}
    pub fn execveat(fd: i32, path: &str, argv: &[&str], envp: &[&str]) {}
    pub fn fork() {}
}
