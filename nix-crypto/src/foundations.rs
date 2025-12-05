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


