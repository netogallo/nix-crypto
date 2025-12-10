use cxx::{CxxString, let_cxx_string};
use std::boxed::{Box};

use crate::cxx_bridge::ffi::{OpensslPrivateKeyIdentity};
use crate::foundations::{CryptoNix, Error};

pub fn rust_add(left: u64, right: u64) -> u64 {
    left + right
}

/// Create a 'CryptoNix' instance. This function accepts
/// a 'CxxString' with the parameters for 'CryptoNix'. It
/// will process the parameters as appropiate and construct
/// an instance of cryptonix configured with the given parameters.
pub fn cryptonix_with_settings(params: &CxxString) -> Box<CryptoNix> {

    let utf8_error = "The path provided to cryptonix is not a valid utf-8 string";

    match (*params).to_str() {
        Ok(rust_params) => {
            panic!("I did not like the paramters {}", rust_params);
            Box::new(CryptoNix::with_directory(rust_params))
        },
        Err(_err) =>
            Box::new(CryptoNix::with_error(Error::CxxError(utf8_error.to_string())))
    }
}

/// Destroy the 'CryptoNix' instance. This function simply
/// takes ownership of the 'CryptoNix' instance which
/// results in it being dropped when the function
/// returns.
pub fn cryptonix_destroy(cryptonix: Box<CryptoNix>) {}

pub type OpensslPrivateKey = crate::openssl::pkey::Key;

impl CryptoNix {

    pub fn cxx_openssl_private_key(self: &CryptoNix, key_identity: OpensslPrivateKeyIdentity) -> Result<Box<OpensslPrivateKey>, Error> {

        let key = self.openssl_private_key(&key_identity)?;
        Ok(Box::new(key))
    }
}
