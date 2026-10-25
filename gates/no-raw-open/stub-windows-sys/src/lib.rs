//! Stub of the `windows-sys` ShellExecute entry points, named so clippy
//! resolves the fixture's FFI call sites to
//! `windows_sys::Win32::UI::Shell::ShellExecute{W,A}`.
#![allow(non_snake_case, clippy::missing_safety_doc, unused_variables)]

pub mod Win32 {
    pub mod UI {
        pub mod Shell {
            pub unsafe fn ShellExecuteW(
                hwnd: isize,
                op: *const u16,
                file: *const u16,
                params: *const u16,
                dir: *const u16,
                show: i32,
            ) -> isize {
                0
            }
            pub unsafe fn ShellExecuteA(
                hwnd: isize,
                op: *const u8,
                file: *const u8,
                params: *const u8,
                dir: *const u8,
                show: i32,
            ) -> isize {
                0
            }
        }
    }
}
