use core::str;
use openssl::error::{ErrorStack};
use std::collections::{HashMap};
use std::fmt;
use std::string;

pub enum Error {
    OpensslError(ErrorStack),
    CxxError(String),
    Utf8Error(str::Utf8Error),
    FromUtf8Error(string::FromUtf8Error)
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Error {
        Error::OpensslError(e)
    }
}

impl From<str::Utf8Error> for Error {
    fn from(e: str::Utf8Error) -> Error {
        Error::Utf8Error(e)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(e: string::FromUtf8Error) -> Error {
        Error::FromUtf8Error(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        match self {
            Error::OpensslError(stack) => stack.fmt(f),
            Error::CxxError(msg) => write!(f, "{}", msg),
            Error::Utf8Error(msg) => msg.fmt(f),
            Error::FromUtf8Error(msg) => msg.fmt(f),
            _ => write!(f, "Unknown error in the 'nix-crypto' Rust code.")
        }
    }
}

impl Error {

    pub fn fail_with<T>(msg: String) -> Result<T, Error> {
        Err(Error::CxxError(msg))
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

