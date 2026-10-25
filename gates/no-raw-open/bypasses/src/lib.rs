//! Every way a consumer might hand a string to the OS to launch. Each call the
//! gate must flag is marked at end of line; the one legitimate opener carries
//! `#[allow(...)]` and must NOT be flagged.
//!
//! The self-test lints this crate with the shipped clippy.toml and checks that
//! the SET of flagged lines equals the SET of marked lines exactly (so a false
//! flag and an escape cannot cancel), and that the allowed opener line is
//! absent.
#![allow(
    unused_variables,
    unused_imports,
    unused_mut,
    dead_code,
    clippy::let_underscore_untyped,
    clippy::no_effect,
    unsafe_code
)]

// renamed import — clippy still resolves `go` to `open::that`
use open::that as go;

pub fn browser_openers(u: &str) {
    open::that(u); // FINDING
    open::that_detached(u); // FINDING
    open::that_in_background(u); // FINDING
    open::with(u, "firefox"); // FINDING
    open::with_detached(u, "firefox"); // FINDING
    go(u); // FINDING
    opener::open(u); // FINDING
    opener::open_browser(u); // FINDING
    webbrowser::open(u); // FINDING
    webbrowser::open_browser(u); // FINDING
}

pub fn std_command(u: &str) {
    std::process::Command::new("/usr/bin/xdg-open").arg(u).status().ok(); // FINDING
    let mut split = std::process::Command::new( // FINDING
        "xdg-open",
    );
    split.arg(u).status().ok();
    std::process::Command::new("sh").arg("-c").arg(format!("open {u}")).status().ok(); // FINDING
    std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", u]).status().ok(); // FINDING
    let prog = "xdg-open";
    std::process::Command::new(prog).arg(u).status().ok(); // FINDING
}

pub fn async_commands(u: &str) {
    tokio::process::Command::new("xdg-open").arg(u); // FINDING
    async_process::Command::new("xdg-open").arg(u); // FINDING
}

pub fn libc_launch(u: &str) {
    let s = b"open url\0";
    let p = s.as_ptr();
    let nul: *const *const u8 = core::ptr::null();
    unsafe {
        libc::system(p); // FINDING
        libc::popen(p, p); // FINDING
        libc::fork(); // FINDING
        libc::execv(p, nul); // FINDING
        libc::execvp(p, nul); // FINDING
        libc::execve(p, nul, nul); // FINDING
        libc::execvpe(p, nul, nul); // FINDING
        libc::execl(p, p); // FINDING
        libc::execlp(p, p); // FINDING
        libc::execle(p, p); // FINDING
        libc::fexecve(0, nul, nul); // FINDING
        let mut pid = 0i32;
        libc::posix_spawn(&mut pid, p, nul, nul); // FINDING
        libc::posix_spawnp(&mut pid, p, nul, nul); // FINDING
    }
}

pub fn nix_launch(u: &str) {
    let argv = ["xdg-open", u];
    nix::unistd::execv("/usr/bin/xdg-open", &argv); // FINDING
    nix::unistd::execve("/usr/bin/xdg-open", &argv, &[]); // FINDING
    nix::unistd::execvp("xdg-open", &argv); // FINDING
    nix::unistd::execvpe("xdg-open", &argv, &[]); // FINDING
    nix::unistd::execveat(0, "xdg-open", &argv, &[]); // FINDING
    nix::unistd::fork(); // FINDING
}

pub fn windows_launch(u: &str) {
    let w: *const u16 = core::ptr::null();
    unsafe {
        windows_sys::Win32::UI::Shell::ShellExecuteW(0, w, w, w, w, 0); // FINDING
        windows_sys::Win32::UI::Shell::ShellExecuteA(0, core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0); // FINDING
        windows_sys::Win32::UI::Shell::ShellExecuteExW(core::ptr::null_mut()); // FINDING
        let mut cmd = [0u16; 4];
        windows_sys::Win32::System::Threading::CreateProcessW(w, cmd.as_mut_ptr(), core::ptr::null(), core::ptr::null(), 0, 0, core::ptr::null(), w, core::ptr::null(), core::ptr::null_mut()); // FINDING
        let mut cmda = [0u8; 4];
        windows_sys::Win32::System::Threading::CreateProcessA(core::ptr::null(), cmda.as_mut_ptr(), core::ptr::null(), core::ptr::null(), 0, 0, core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null_mut()); // FINDING
    }
}

/// The single legitimate opener: it already holds a checked URL, so this one
/// raw open is allowed. It must NOT be a finding.
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the one opener; the URL is already checked"
)]
pub fn the_only_allowed_opener(checked_url: &str) {
    open::that(checked_url); // ALLOWED
}
