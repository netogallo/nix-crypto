use cxx::{CxxString};
use std::boxed::{Box};

use crate::cxx_bridge::ffi::{OpensslPrivateKeyIdentity, X509BuildParams};
use crate::error::{Error};
use crate::foundations::{CryptoNix};

pub fn rust_add(left: u64, right: u64) -> u64 {
    left + right
}

/// Create a 'CryptoNix' instance. This function accepts
/// a 'CxxString' with the parameters for 'CryptoNix'. It
/// will process the parameters as appropiate and construct
/// an instance of cryptonix configured with the given parameters.
pub fn cryptonix_with_settings(params: &CxxString) -> Box<CryptoNix> {

    let utf8_error = "Unexpected error in CryptoNix. The arguments supplied are not a valid utf-8 string. Please report this bug!";

    match params.to_str() {
        Ok(rust_params) => {
            Box::new(CryptoNix::with_args(rust_params))
        },
        Err(_err) =>
            Box::new(CryptoNix::with_error(Error::CxxError(utf8_error.to_string())))
    }
}

pub type OpensslPrivateKey = crate::openssl::pkey::Key;

pub type OpensslX509Certificate = crate::openssl::x509::X509Certificate;

impl IsCryptoStoreKey for ffi::OpensslPrivateKeyIdentity {
    type Value = pkey::Key;

    fn to_store_key_raw(&self, salt: &[u8]) -> Vec<u8> {
        let mut hasher = sha::Sha256::new();
        hasher.update(salt);
        hasher.update(self.key_type.as_bytes());
        hasher.update(self.key_id.as_bytes());
        Vec::from(hasher.finish())
    }

    fn to_store_value_raw(value: &pkey::Key) -> Result<Vec<u8>, Error> {
        let result = value.pkey.private_key_to_pem_pkcs8()?;
        Ok(result)
    }

    fn from_store_value_raw(bytes: &Vec<u8>) -> Result<pkey::Key, Error> {
        let result = pkey::Key::from_openssl_pkey(
            PKey::private_key_from_pem(&bytes[..])?
        );
        Ok(result)
    }
}

impl CryptoNix {

    pub fn cxx_openssl_private_key(self: &CryptoNix, key_identity: OpensslPrivateKeyIdentity) -> Result<Box<OpensslPrivateKey>, Error> {

        let key = self.openssl_private_key(&key_identity)?;
        Ok(Box::new(key))
    }

    pub fn cxx_openssl_x509_certificate(&self, args: X509BuildParams) -> Result<Box<OpensslX509Certificate>, Error> {
        let result = self.openssl_x509_certificate(&args)?;
        Ok(Box::new(result))
    }
}
