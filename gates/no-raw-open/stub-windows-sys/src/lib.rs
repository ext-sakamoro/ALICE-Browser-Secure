//! Stub of the `windows-sys` launch entry points, named so clippy resolves the
//! fixture's FFI call sites to the real paths. Signatures are simplified.
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
            pub unsafe fn ShellExecuteExW(info: *mut u8) -> i32 {
                0
            }
        }
    }
    pub mod System {
        pub mod Threading {
            pub unsafe fn CreateProcessW(
                app: *const u16,
                cmd: *mut u16,
                proc_attrs: *const u8,
                thread_attrs: *const u8,
                inherit: i32,
                flags: u32,
                env: *const u8,
                cwd: *const u16,
                startup: *const u8,
                info: *mut u8,
            ) -> i32 {
                0
            }
            pub unsafe fn CreateProcessA(
                app: *const u8,
                cmd: *mut u8,
                proc_attrs: *const u8,
                thread_attrs: *const u8,
                inherit: i32,
                flags: u32,
                env: *const u8,
                cwd: *const u8,
                startup: *const u8,
                info: *mut u8,
            ) -> i32 {
                0
            }
        }
    }
}
