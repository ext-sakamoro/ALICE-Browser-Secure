//! Every way a consumer might hand a string to the OS to launch. Each call the
//! gate must flag is marked at end of line; the one legitimate opener carries
//! `#[allow(clippy::disallowed_methods)]` and must NOT be flagged.
//!
//! The self-test lints this crate with the shipped clippy.toml and checks that
//! clippy's `disallowed_methods` count equals the number of marked call lines.
#![allow(
    unused_variables,
    unused_imports,
    dead_code,
    clippy::let_underscore_untyped,
    clippy::no_effect,
    unsafe_code
)]

use std::process::Command;

// renamed import — clippy still resolves `go` to `open::that`
use open::that as go;

pub fn opener_crate_shapes(u: &str) {
    open::that(u); // FINDING  (plain, 9e's control)
    open::that_detached(u); // FINDING
    open::that_in_background(u); // FINDING
    open::with(u, "firefox"); // FINDING
    open::with_detached(u, "firefox"); // FINDING
    go(u); // FINDING  (use open::that as go)
    opener::open(u); // FINDING
    opener::open_browser(u); // FINDING
    webbrowser::open(u); // FINDING
    webbrowser::open_browser(u); // FINDING
}

pub fn command_shapes(u: &str) {
    Command::new("/usr/bin/xdg-open").arg(u).status().ok(); // FINDING  (absolute path)
    Command::new(
        "xdg-open", // FINDING  (split across lines)
    )
    .arg(u)
    .status()
    .ok();
    Command::new("sh")
        .arg("-c")
        .arg(format!("open {u}"))
        .status()
        .ok(); // FINDING  (sh -c)
    Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", u])
        .status()
        .ok(); // FINDING  (rundll32)
    let prog = "xdg-open";
    Command::new(prog).arg(u).status().ok(); // FINDING  (aliased variable)
}

pub fn ffi_shapes(u: &str) {
    let cmd = b"open url\0";
    unsafe {
        libc::system(cmd.as_ptr()); // FINDING
        libc::execv(cmd.as_ptr(), core::ptr::null()); // FINDING
        libc::execvp(cmd.as_ptr(), core::ptr::null()); // FINDING
        let mut pid = 0i32;
        libc::posix_spawn(&mut pid, cmd.as_ptr(), core::ptr::null(), core::ptr::null()); // FINDING
        windows_sys::Win32::UI::Shell::ShellExecuteW(
            0,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            0,
        ); // FINDING  (windows ShellExecuteW)
    }
}

/// The single legitimate opener: it already holds a checked URL, so this one
/// raw open is allowed. It must NOT be a finding.
#[allow(clippy::disallowed_methods, reason = "the one opener; the URL is already checked")]
pub fn the_only_allowed_opener(checked_url: &str) {
    open::that(checked_url); // ALLOWED
}
