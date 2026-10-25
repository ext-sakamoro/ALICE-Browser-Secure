//! Stub of the `libc` process-launching entry points, named so clippy resolves
//! the fixture's FFI call sites to `libc::*`. Signatures are simplified; clippy
//! disallows by path, not by signature.
#![allow(clippy::missing_safety_doc, unused_variables, non_camel_case_types)]

pub unsafe fn system(cmd: *const u8) -> i32 {
    0
}
pub unsafe fn popen(cmd: *const u8, mode: *const u8) -> *mut u8 {
    core::ptr::null_mut()
}
pub unsafe fn fork() -> i32 {
    0
}
pub unsafe fn execv(path: *const u8, argv: *const *const u8) -> i32 {
    0
}
pub unsafe fn execvp(file: *const u8, argv: *const *const u8) -> i32 {
    0
}
pub unsafe fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32 {
    0
}
pub unsafe fn execvpe(file: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32 {
    0
}
pub unsafe fn execl(path: *const u8, arg0: *const u8) -> i32 {
    0
}
pub unsafe fn execlp(file: *const u8, arg0: *const u8) -> i32 {
    0
}
pub unsafe fn execle(path: *const u8, arg0: *const u8) -> i32 {
    0
}
pub unsafe fn fexecve(fd: i32, argv: *const *const u8, envp: *const *const u8) -> i32 {
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
pub unsafe fn posix_spawnp(
    pid: *mut i32,
    file: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> i32 {
    0
}
