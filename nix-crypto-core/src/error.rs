use core::str;
use openssl::error::{ErrorStack};
use std::fmt;
use std::string;

/// The type used to represent errors that occur
/// within the 'CryptoNix' crate. All functions
/// that can fail will fail with this error type.
#[derive(Clone)]
#[derive(Debug)]
pub enum Error {
    OpensslError(ErrorStack),
    CxxError(String),
    Utf8Error(str::Utf8Error),
    FromUtf8Error(string::FromUtf8Error),
    SledError(sled::Error),
    CryptoNixError(String),
    CryptoNixErrorRef(&'static str),
    TimeParseError(time::error::Parse),

    /// Used to indicate an error occured when
    /// serializing or deserializing json-encoded
    /// binary data via serde. The `serde_json::Error`
    /// type does not implement `Clone`, therefore we
    /// save the error as `String`.
    SerdeJsonError(String)
}

impl From<time::error::Parse> for Error {
    fn from(e: time::error::Parse) -> Error {
        Error::TimeParseError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJsonError(format!("{e:#?}"))
    }
}

impl From<sled::Error> for Error {
    fn from(e: sled::Error) -> Error {
        Error::SledError(e)
    }
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
            Error::CryptoNixError(msg) => msg.fmt(f),
            Error::CryptoNixErrorRef(msg) => msg.fmt(f),
            _ => write!(f, "Unknown error in the 'nix-crypto' Rust code.")
        }
    }
}

impl From<&'static str> for Error {
    fn from(msg: &'static str) -> Error {
        Error::CryptoNixErrorRef(msg)
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Error {
        Error::CryptoNixError(msg)
    }
}

impl Error {

    pub fn fail_with<T>(msg: String) -> Result<T, Error> {
        Err(Error::from_message(msg))
    }

    pub fn from_message(msg: String) -> Error {
        Error::CryptoNixError(msg)
    }
}
