use cxx::{CxxString};
use std::boxed::{Box};

// Imports from sister crates
use nix_crypto_core::error::{Error};
use nix_crypto_core::foundations::{CryptoNix};
use nix_crypto_core::store::{IsCryptoStoreKey, StoreHasher};
use nix_crypto_core::openssl::pkey;

// Imports from this crate
use crate::cxx_bridge::ffi::{OpensslPrivateKeyIdentity, X509BuildParams};

pub fn rust_add(left: u64, right: u64) -> u64 {
    left + right
}

/// CXX wrapper type for "CryptoNix". This is meant to expose
/// the nix-crypto interface that will be accesible in C++
pub struct CxxNixCrypto(CryptoNix);

/// Create a 'CxxNixCrypto' instance. This function accepts
/// a 'CxxString' with the parameters for nix-crypto. It
/// will process the parameters as appropiate and construct
/// an instance of cryptonix configured with the given parameters.
pub fn nix_crypto_with_settings(params: &CxxString) -> Box<CxxNixCrypto> {

    let utf8_error = "Unexpected error in CryptoNix. The arguments supplied are not a valid utf-8 string. Please report this bug!";

    let nix_crypto = match params.to_str() {
        Ok(rust_params) => {
            CryptoNix::with_args(rust_params)
        },
        Err(_err) =>
            CryptoNix::with_error(Error::CxxError(utf8_error.to_string()))
    };
    Box::new(CxxNixCrypto(nix_crypto))
}

pub struct CxxOpensslPrivateKey(nix_crypto_core::openssl::pkey::Key);

impl CxxOpensslPrivateKey {
    pub fn public_pem(&self) -> Result<String, Error> {
        self.0.public_pem()
    }
}

pub struct CxxOpensslX509Certificate(nix_crypto_core::openssl::x509::X509Certificate);

impl CxxOpensslX509Certificate {
    pub fn public_pem(&self) -> Result<String, Error> {
        self.0.public_pem()
    }
}

impl IsCryptoStoreKey for OpensslPrivateKeyIdentity {
    type Value = pkey::Key;

    fn to_store_key_raw(&self, mut hasher: StoreHasher) -> Vec<u8> {
        hasher.update(self.key_type.as_bytes());
        hasher.update(self.key_id.as_bytes());
        Vec::from(hasher.finish())
    }

    fn to_store_value_raw(value: &pkey::Key) -> Result<Vec<u8>, Error> {
        pkey::Key::key_to_pem(value)
    }

    fn from_store_value_raw(bytes: &Vec<u8>) -> Result<pkey::Key, Error> {
        pkey::Key::key_from_pem(&bytes[..])
    }
}

impl CxxNixCrypto {

    pub fn cxx_openssl_private_key(self: &CxxNixCrypto, key_identity: OpensslPrivateKeyIdentity) -> Result<Box<CxxOpensslPrivateKey>, Error> {

        let key = self.0.openssl_private_key(&key_identity)?;
        Ok(Box::new(CxxOpensslPrivateKey(key)))
    }

    pub fn cxx_openssl_x509_certificate(&self, args: X509BuildParams) -> Result<Box<CxxOpensslX509Certificate>, Error> {
        let result = self.0.openssl_x509_certificate(&args)?;
        Ok(Box::new(CxxOpensslX509Certificate(result)))
    }
}
