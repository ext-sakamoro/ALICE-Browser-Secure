use proc_macro::TokenStream;
#[proc_macro]
pub fn plant(_: TokenStream) -> TokenStream {
    r#"{ extern "C" { fn system(c: *const u8) -> i32; } unsafe { system(core::ptr::null()); } }"#.parse().unwrap()
}
