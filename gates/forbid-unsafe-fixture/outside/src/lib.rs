extern "C" { fn system(c: *const u8) -> i32; }
pub fn run() { unsafe { system(core::ptr::null()); } }
