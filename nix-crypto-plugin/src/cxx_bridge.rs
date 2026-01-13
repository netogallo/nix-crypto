// This module will get parsed by the cxx:builder. Avoid anything
// other than definitions strictly needed for the C++ bridge, as
// any changes here incurr long re-compilation. For utilities
// related to the CXX bridge, use the cxx_support module. Function
// implementations for the functions in this module should be placed
// in cxx_api
use cxx::{CxxString, UniquePtr};

use nix_crypto_core::error::{Error};
use nix_crypto_core::foundations::{CryptoNix};
use nix_crypto_core::openssl::ffi::*;

use crate::cxx_api::*;

#[cxx::bridge]
pub mod ffi {

    extern "Rust" {

        type CryptoNix;
        type OpensslPrivateKey;
        type OpensslX509Certificate;

        fn cryptonix_with_settings(settings: &CxxString) -> Box<CryptoNix>;
        fn rust_add(left: u64, right: u64) -> u64;

        fn cxx_openssl_private_key(self: &CryptoNix, key_identity: OpensslPrivateKeyIdentity) -> Result<Box<OpensslPrivateKey>>;

        fn cxx_openssl_x509_certificate(self: &CryptoNix, args: X509BuildParams) -> Result<Box<OpensslX509Certificate>>;

        fn public_pem(self: &OpensslPrivateKey) -> Result<String>;

        fn public_pem(self: &OpensslX509Certificate) -> Result<String>;
    }

    unsafe extern "C++" {
        include!("nix-crypto/include/nix_crypto.hh");

        fn init_primops();

        fn destroy_primops();
    }
}
