use ctor::{ctor,dtor};
use cxx::{UniquePtr};
use std::ffi::{c_int};
use std::cell::{OnceCell};

use crate::foundations::{CryptoNixManaged};

//#[unsafe(no_mangle)]
// pub extern "C"
fn rust_add(left: u64, right: u64) -> u64 {
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

#[cxx::bridge]
mod ffi {
    extern "Rust" {
        fn rust_add(left: u64, right: u64) -> u64;
    }

    unsafe extern "C++" {
        include!("nix-crypto/include/nix_crypto.hh");

        fn init_primops();

        fn destroy_primops();
    }
}

#[ctor]
fn init() {
    ffi::init_primops();
}

#[dtor]
fn exit() {
    ffi::destroy_primops();
}

mod foundations;
mod age;
mod openssl;
