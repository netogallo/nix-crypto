use std::ffi::{c_int};

use crate::foundations::{CryptoNixManaged};

#[unsafe(no_mangle)]
pub extern "C" fn rust_add(left: c_int, right: c_int) -> c_int {
    left + right
}

#[unsafe(no_mangle)]
pub extern "C" fn cryptonix_with_directory() -> *mut CryptoNixManaged {
	Box::into_raw(Box::new(CryptoNixManaged::with_directory()))
}

#[unsafe(no_mangle)]
pub extern "C" fn cryptonix_delete(ptr: *mut CryptoNixManaged) {
	if !ptr.is_null() {
		unsafe { drop(Box::from_raw(ptr)) }
	}
}

mod foundations;
mod age;
mod openssl;
