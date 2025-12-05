use std::ffi::{c_int};

mod foundations;
mod age;
mod openssl;

#[unsafe(no_mangle)]
pub extern "C" fn rust_add(left: c_int, right: c_int) -> c_int {
    left + right
}
