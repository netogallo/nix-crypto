use cxx::{CxxString};

use crate::cxx_api::*;
use crate::openssl;
use crate::foundations::{CryptoNix};

#[cxx::bridge]
pub mod ffi {
    extern "Rust" {

        type CryptoNix;

        unsafe fn cryptonix_with_directory(path: &CxxString) -> *mut CryptoNix;
        unsafe fn cryptonix_destroy(cryptonix: *mut CryptoNix);
        fn rust_add(left: u64, right: u64) -> u64;

        type OpensslPrivateKey;
        fn cxx_openssl_private_key(self: &CryptoNix, key_type: &CxxString, identity: &CxxString) -> Result<Box<OpensslPrivateKey>>;

        fn public_pem(self: &OpensslPrivateKey) -> Result<String>;

    }

    unsafe extern "C++" {
        include!("nix-crypto/include/nix_crypto.hh");

        fn init_primops();

        fn destroy_primops();
    }
}
