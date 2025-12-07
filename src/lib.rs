use ctor::{ctor,dtor};
use cxx::{CxxString};
use std::boxed::{Box};
use std::ffi::{c_int};
use std::cell::{OnceCell};


mod foundations;
mod age;
mod openssl;

use crate::foundations::{CryptoNix, Error};

fn rust_add(left: u64, right: u64) -> u64 {
    left + right
}

/// Create a managed instance of 'CryptoNix' using a filesystem
/// directory as store. This function will create a directory located
/// at the specified 'path' (if missing). This directory will be used
/// to store all the private cryptographic keys. If 'path'
/// already exist, it is exepcted to be a store from previous usages
/// of 'CryptoNix'. The managed pointer must be manually destroyed
/// using the 'cryptonix_destroy' function.
unsafe fn cryptonix_with_directory(path: &CxxString) -> *mut CryptoNix {

    let utf8_error = "The path provided to cryptonix is not a valid utf-8 string";

    unsafe {
        match (*path).to_str() {
            Ok(rust_path) => Box::into_raw(
                Box::new(CryptoNix::with_directory(rust_path.to_string()))
            ),
            Err(_err) => Box::into_raw(
                Box::new(CryptoNix::with_error(Error::CxxError(utf8_error.to_string())))
            )
        }
    }
}

/// Destroy a manged instance of 'CryptoNix'.
unsafe fn cryptonix_destroy(cryptonix: *mut CryptoNix) {
    unsafe {
        let _ = Box::from_raw(cryptonix);
    }
}

type OpensslPrivateKey = crate::openssl::pkey::Key;

impl CryptoNix {

    pub fn cxx_openssl_private_key(self: &CryptoNix, key_type: &CxxString, identity: &CxxString) -> Result<Box<OpensslPrivateKey>, Error> {

        let key_type_rs = (*key_type).to_str()?;
        let identity_rs = (*identity).to_str()?;
        let key = self.openssl_private_key(key_type_rs, identity_rs)?;
        Ok(Box::new(key))
    }
}

#[cxx::bridge]
mod ffi {
    extern "Rust" {

        type CryptoNix;

        unsafe fn cryptonix_with_directory(path: &CxxString) -> *mut CryptoNix;
        unsafe fn cryptonix_destroy(cryptonix: *mut CryptoNix);
        fn rust_add(left: u64, right: u64) -> u64;

        type OpensslPrivateKey;
        fn cxx_openssl_private_key(self: &CryptoNix, key_type: &CxxString, identity: &CxxString) -> Result<Box<OpensslPrivateKey>>;

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


