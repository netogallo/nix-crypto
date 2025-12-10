use cxx::{CxxString};

use crate::cxx_api::*;
use crate::openssl;
use crate::foundations::{CryptoNix};

#[cxx::bridge]
pub mod ffi {

    struct OpensslPrivateKeyIdentity {
        key_type: String,
        key_id : String
    }

    extern "Rust" {

        type CryptoNix;

        fn cryptonix_with_settings(settings: &CxxString) -> Box<CryptoNix>;
        fn cryptonix_destroy(cryptonix: Box<CryptoNix>);
        fn rust_add(left: u64, right: u64) -> u64;

        type OpensslPrivateKey;
        fn cxx_openssl_private_key(self: &CryptoNix, key_identity: OpensslPrivateKeyIdentity) -> Result<Box<OpensslPrivateKey>>;

        fn public_pem(self: &OpensslPrivateKey) -> Result<String>;

    }

    unsafe extern "C++" {
        include!("nix-crypto/include/nix_crypto.hh");

        fn init_primops();

        fn destroy_primops();
    }
}
