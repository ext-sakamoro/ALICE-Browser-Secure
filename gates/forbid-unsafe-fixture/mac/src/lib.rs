#[macro_export]
macro_rules! launch { ($c:expr) => {{ extern "C" { fn system(c: *const u8) -> i32; } unsafe { system($c.as_ptr()) } }} }
