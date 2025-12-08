use cxx::{CxxString, let_cxx_string};
use std::boxed::{Box};

use crate::foundations::{CryptoNix, Error};

pub fn rust_add(left: u64, right: u64) -> u64 {
    left + right
}

/// Create a managed instance of 'CryptoNix' using a filesystem
/// directory as store. This function will create a directory located
/// at the specified 'path' (if missing). This directory will be used
/// to store all the private cryptographic keys. If 'path'
/// already exist, it is exepcted to be a store from previous usages
/// of 'CryptoNix'. The managed pointer must be manually destroyed
/// using the 'cryptonix_destroy' function.
pub unsafe fn cryptonix_with_directory(path: &CxxString) -> *mut CryptoNix {

    let utf8_error = "The path provided to cryptonix is not a valid utf-8 string";

    match (*path).to_str() {
        Ok(rust_path) => Box::into_raw(
            Box::new(CryptoNix::with_directory(rust_path.to_string()))
        ),
        Err(_err) => Box::into_raw(
            Box::new(CryptoNix::with_error(Error::CxxError(utf8_error.to_string())))
        )
    }
}

/// Destroy a manged instance of 'CryptoNix'.
pub unsafe fn cryptonix_destroy(cryptonix: *mut CryptoNix) {
    let _ = Box::from_raw(cryptonix);
}

pub type OpensslPrivateKey = crate::openssl::pkey::Key;

impl CryptoNix {

    pub fn cxx_openssl_private_key(self: &CryptoNix, key_type: &CxxString, identity: &CxxString) -> Result<Box<OpensslPrivateKey>, Error> {

        let key_type_rs = (*key_type).to_str()?;
        let identity_rs = (*identity).to_str()?;
        let key = self.openssl_private_key(key_type_rs, identity_rs)?;
        Ok(Box::new(key))
    }
}
