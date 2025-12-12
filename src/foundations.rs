use std::borrow::{Borrow};
use std::collections::{HashMap};

use crate::args::{CryptoNixArgs, CryptoNixMode, SledModeConfig};
use crate::error::*;

pub trait IsCryptoStoreKey {
    fn into_crypto_store_key(&self, salt: &[u8]) -> Vec<u8>;
}

/// The 'CryptoStore' defines the behavior expected from
/// values capable of storing and retrieving cryptographic
/// secrets. These secrets can be private-keys, passwords,
/// symmetric keys, amoong other things.
pub trait CryptoStore {
    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn put_raw(&self, key: &[u8], value: Vec<u8>) -> Result<(), Error>;

    /// This function should return a salt that 'CryptoNix' will use
    /// to hash values. The salt is expected to be unique per store instance
    /// and to remain constant whenever the same store is intialized upon
    /// different runs of the program.
    fn salt(&self) -> Vec<u8>;
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
    error: Error
}

impl ErrorStore {
    pub fn from_error(error: Error) -> ErrorStore {
        ErrorStore { error: error }
    }
}

// Todo: A salt should be generated upon the store initialization
// and use that salt instead
static SALT : &[u8] = "72d12af4-adf5-42f6-938f-d504210d5492".as_bytes();

impl CryptoStore for ErrorStore {

    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Err(self.error.clone())
    }

    fn put_raw(&self, key: &[u8], value: Vec<u8>) -> Result<(), Error> {
        Err(self.error.clone())
    }

    fn salt(&self) -> Vec<u8> {
        Vec::from(SALT)
    }
}

/// The 'SledStore' implements a 'CryptoStore' using
/// the 'sled' crate as the storage backend.
struct SledStore {
    sled_db : sled::Db
}

impl CryptoStore for SledStore {

    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let value = self.sled_db.get(key)?;
        Ok(
            value.map(|iv| iv.to_vec())
        )
    }

    fn put_raw(&self, key: &[u8], value: Vec<u8>) -> Result<(), Error> {

        if self.sled_db.contains_key(key)? {
            return Error::fail_with("Bug in CryptoNix. An attempt was made to replace an existing key in the store. Please report this issue.".to_string());
        }
        let _ = self.sled_db.insert(key, value)?;
        Ok(())
    }

    fn salt(&self) -> Vec<u8> {
        // Todo: Salt should be generated for every instance and
        // saved in the sled store
        Vec::from(SALT)
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

    /// Try getting a value from the 'CryptoStore' which is associated
    /// with the 'key' parameter. If the value does not exist in the
    /// store, 'Nothing' is returned. Otherwise the value gets returned.
    /// This function might raise 'Error' if there is a fundamental issue
    /// with the store which prevents it from being read.
    pub fn get<K: IsCryptoStoreKey, V: for<'v> TryFrom<&'v Vec<u8>, Error = Error>>(&self, key: &K) -> Result<Option<V>, Error> {

        match self.store.get_raw(&key.into_crypto_store_key(&self.salt()[..])[..])? {
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
            &key.into_crypto_store_key(&self.salt()[..])[..],
            Vec::try_from(value)?
        )
    }

    pub fn salt(&self) -> Vec<u8> {
        self.store.salt()
    }

    fn from_sled_config(config: &SledModeConfig) -> CryptoNix {

        match SledStore::open(&config.store_path) {
            Ok(store) => CryptoNix { store: Box::new(store) },
            Err(err) => Self::with_error(err)
        }
    }

    fn from_parsed_args(args: CryptoNixArgs) -> CryptoNix {

        match args.mode {
            CryptoNixMode::SledMode(sled) => Self::from_sled_config(&sled),
            CryptoNixMode::ErrorMode(err) => Self::with_error(err)
        }
    }

    /// Parse the arguments and build a CryptoNix instance
    /// based on said argumetns. If the arguments cannot be parsed,
    /// an instance will be constructed which will fail on every
    /// operation. CryptoNix, in general, uses this approach to allow
    /// enabling the plugin systemwide and not having nix crash
    /// if invoked w/o parameters.
    pub fn with_args(args: &str) -> CryptoNix {
        Self::from_parsed_args(CryptoNixArgs::from_args(args))
    }

    pub fn with_error(error: Error) -> CryptoNix {
        CryptoNix{
            store : Box::new(ErrorStore::from_error(error))
        }
    }
}
