use core::str;
use openssl::error::{ErrorStack};
use std::borrow::{Borrow};
use std::collections::{HashMap};
use std::fmt;
use std::string;

pub enum Error {
    OpensslError(ErrorStack),
    CxxError(String),
    Utf8Error(str::Utf8Error),
    FromUtf8Error(string::FromUtf8Error),
    SledError(sled::Error)
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
            _ => write!(f, "Unknown error in the 'nix-crypto' Rust code.")
        }
    }
}

impl Error {

    pub fn fail_with<T>(msg: String) -> Result<T, Error> {
        Err(Error::CxxError(msg))
    }
}

pub trait IsCryptoStoreKey {
    fn into_crypto_store_key(&self) -> Vec<u8>;
}

/// The 'CryptoStore' defines the behavior expected from
/// values capable of storing and retrieving cryptographic
/// secrets. These secrets can be private-keys, passwords,
/// symmetric keys, amoong other things.
pub trait CryptoStore {
    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn put_raw(&self, key: &[u8], value: &Vec<u8>) -> Result<(), Error>;
}

pub trait CryptoStoreExtensions {
    fn get<K: IsCryptoStoreKey, V: for<'v> TryFrom<&'v Vec<u8>, Error = Error>>(&self, key: K) -> Result<Option<V>, Error>;
}

/// The 'ErrorStore' represents a store that will fail
/// on every operation. This is meant to avoid the
/// case of Nix hard-crashing if the store cannot
/// be initialized. Instead, functions using the
/// store will produce an error.
struct ErrorStore {
}

impl CryptoStore for ErrorStore {

    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        panic!("Not implemented")
    }

    fn put_raw(&self, key: &[u8], value: &Vec<u8>) -> Result<(), Error> {
        panic!("Not implemented")
    }
}

/// The 'SledStore' implements a 'CryptoStore' using
/// the 'sled' crate as the storage backend.
struct SledStore {
    sled_db : sled::Db
}

impl CryptoStore for SledStore {

    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        panic!("Not implemented")
    }

    fn put_raw(&self, key: &[u8], value: &Vec<u8>) -> Result<(), Error> {
        panic!("Not implemented")
    }
}

impl SledStore {
    pub fn open(path: &str) -> Result<SledStore, Error> {
        let db = sled::open(path)?;
        Ok(SledStore { sled_db : db })
    }
}

pub struct CryptoNix {
    store : Box<dyn CryptoStore>
}

impl CryptoNix {


    pub fn get<K: IsCryptoStoreKey, V: for<'v> TryFrom<&'v Vec<u8>, Error = Error>>(&self, key: &K) -> Result<Option<V>, Error> {

        match self.store.get_raw(&key.into_crypto_store_key()[..])? {
            Some(vec) => Ok(Some(V::try_from(&vec)?)),
            _ => Ok(None)
        }
    }

    pub fn put<K: IsCryptoStoreKey, V>(
        &self,
        key: &K,
        value: &V
    ) -> Result<(), Error>
    where Vec<u8> : for<'a> TryFrom<&'a V, Error = Error> {
        self.store.put_raw(
            &key.into_crypto_store_key()[..],
            &Vec::try_from(value)?
        )
    }

    pub fn with_directory(path : &str) -> CryptoNix {

        match SledStore::open(path) {
            Ok(store) => CryptoNix{ store : Box::new(store) },
            Err(err) => CryptoNix::with_error(err)
        }
    }

    pub fn with_error(error: Error) -> CryptoNix {
        CryptoNix{
            store : Box::new(ErrorStore{})
        }
    }
}

