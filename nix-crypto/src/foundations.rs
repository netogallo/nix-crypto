use openssl::error::{ErrorStack};
use std::collections::{HashMap};

pub enum Error {
    OpensslError(ErrorStack)
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Error {
        Error::OpensslError(e)
    }
}

pub struct CryptoNix {}

impl CryptoNix {

    pub fn with_directory() -> CryptoNix {
        CryptoNix{}
    }
}

#[repr(C)]
pub struct CryptoNixManaged {
    cryptonix : CryptoNix
}

impl CryptoNixManaged {

    pub fn with_directory() -> CryptoNixManaged {

        CryptoNixManaged { cryptonix: CryptoNix::with_directory() }
    }
}

