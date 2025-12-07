use openssl::error::{ErrorStack};
use std::collections::{HashMap};

pub enum Error {
    OpensslError(ErrorStack),
    CxxError(String)
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Error {
        Error::OpensslError(e)
    }
}

pub struct CryptoNix {}

impl CryptoNix {

    pub fn with_directory(path : String) -> CryptoNix {
        CryptoNix{}
    }

    pub fn with_error(error: Error) -> CryptoNix {
        CryptoNix{}
    }
}

