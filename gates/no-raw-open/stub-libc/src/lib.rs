//! Stub of the `libc` process-launching entry points, named so clippy resolves
//! the fixture's FFI call sites to `libc::*`. Signatures are simplified; clippy
//! disallows by path, not by signature.
#![allow(clippy::missing_safety_doc, unused_variables)]

pub unsafe fn system(cmd: *const u8) -> i32 {
    0
}
pub unsafe fn execv(path: *const u8, argv: *const *const u8) -> i32 {
    0
}
pub unsafe fn execvp(file: *const u8, argv: *const *const u8) -> i32 {
    0
}
pub unsafe fn posix_spawn(
    pid: *mut i32,
    path: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> i32 {
    0
}
