use std::borrow::{Borrow};

use crate::args::{CryptoNixArgs, CryptoNixMode, SledModeConfig};
use crate::error::*;
use crate::store::*;

pub struct CryptoNix {
    store : Box<dyn CryptoStore>
}

impl CryptoNix {

    fn to_store_key_raw<Key: IsCryptoStoreKey>(&self, key: &Key) -> Vec<u8> {
        let hasher = StoreHasher::init(&self.salt());
        key.to_store_key_raw(hasher)
    }

    /// Try getting a value from the 'CryptoStore' which is associated
    /// with the 'key' parameter. If the value does not exist in the
    /// store, 'Nothing' is returned. Otherwise the value gets returned.
    /// This function might raise 'Error' if there is a fundamental issue
    /// with the store which prevents it from being read.
    pub fn get<K: IsCryptoStoreKey>(
        &self,
        key: &K
    ) -> Result<Option<<K as IsCryptoStoreKey>::Value>, Error> {

        match self.store.get_raw(&self.to_store_key_raw(key)[..])? {
            Some(vec) => Ok(Some(<K as IsCryptoStoreKey>::from_store_value_raw(&vec)?)),
            _ => Ok(None)
        }
    }

    pub fn put<K: IsCryptoStoreKey>(
        &self,
        key: &K,
        value: &<K as IsCryptoStoreKey>::Value
    ) -> Result<(), Error>
    where {

        self.store.put_raw(
            &self.to_store_key_raw(key)[..],
            <K as IsCryptoStoreKey>::to_store_value_raw(value)?
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
