use crate::args::{CryptoNixArgs, CryptoNixMode, SledModeConfig};
use crate::error::*;
use crate::logger::{Logger, LogLevel};
use crate::store::*;

pub struct CryptoNix {
    store: Box<dyn CryptoStore>,
    logger: Logger,
}

/// This trait is meant to represent store keys which can be
/// used to derive the value which they intent to represent.
/// Many store keys have that property as they are usually
/// compromise a full spec of parameters that can be used
/// to derive a valid instance of the underlying value.
pub trait IsCryptoStoreKeyDerivable : IsCryptoStoreKey {

    fn derive(&self) -> Result<<Self as IsCryptoStoreKey>::Value, Error>;
}

pub struct AsDerivable<'a, T>(&'a T);

impl<'a, T : IsCryptoStoreKey> IsCryptoStoreKey for AsDerivable<'a, T> {
    type Value = <T as IsCryptoStoreKey>::Value;

    fn to_store_key_raw(&self, hasher: StoreHasher) -> Vec<u8> {
        self.0.to_store_key_raw(hasher)
    }

    fn to_store_value_raw(value: &Self::Value) -> Result<Vec<u8>, Error> {
        <T as IsCryptoStoreKey>::to_store_value_raw(value)
    }

    fn from_store_value_raw(value: &Vec<u8>) -> Result<Self::Value, Error> {
        <T as IsCryptoStoreKey>::from_store_value_raw(value)
    }
}

impl CryptoNix {

    fn to_store_key_raw<Key: IsCryptoStoreKey>(&self, key: &Key) -> Vec<u8> {
        let hasher = StoreHasher::init(&self.salt());
        key.to_store_key_raw(hasher)
    }

    /// Public wrapper around `to_store_key_raw`. Needed by external modules
    /// such as `decryptable` that must compute raw store keys in order to
    /// build composite keys (e.g. `EncryptionParamsKey`).
    pub fn to_store_key_raw_pub<Key: IsCryptoStoreKey>(&self, key: &Key) -> Vec<u8> {
        self.to_store_key_raw(key)
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

        let raw_key = self.to_store_key_raw(key);
        let identity = self.logger.to_log_identifier(&raw_key);
        let fn_name = "foundations::CryptoNix::get";

        match self.store.get_raw(&raw_key[..])? {
            Some(raw_value) => {
                self.logger.log(
                    LogLevel::Debug,
                    "identity present",
                    &[
                        ("identity", &identity),
                        ("fn", &fn_name)
                    ],
                );
                Ok(Some(<K as IsCryptoStoreKey>::from_store_value_raw(&raw_value)?))
            },
            None => {
                self.logger.log(
                    LogLevel::Debug,
                    "identity absent",
                    &[
                        ("identity", &identity),
                        ("fn", &fn_name)
                    ],
                );
                Ok(None)
            },
        }
    }

    pub fn get_or_derive<K: IsCryptoStoreKeyDerivable>(
        &self,
        key: &K
    ) -> Result<<K as IsCryptoStoreKey>::Value, Error> {

        match self.get(key)? {
            Some(raw_value) => Ok(raw_value),
            None => {
                self.logger.log(
                    LogLevel::Debug,
                    "deriving value",
                    &[
                        ("fn", "foundations::CryptoNix::get_or_derive")
                    ],
                );
                let value = key.derive()?;
                self.put(key, &value)?;
                Ok(value)
            }
        }
    }

    pub fn put<K: IsCryptoStoreKey>(
        &self,
        key: &K,
        value: &<K as IsCryptoStoreKey>::Value
    ) -> Result<(), Error> {

        self.store.put_raw(
            &self.to_store_key_raw(key)[..],
            <K as IsCryptoStoreKey>::to_store_value_raw(value)?
        )
    }

    pub fn salt(&self) -> Vec<u8> {
        self.store.salt()
    }

    /// Construct a `CryptoNix` instance from a sled store configuration
    /// and a logger.
    pub fn from_sled_config(config: &SledModeConfig, logger: Logger) -> CryptoNix {
        match SledStore::open(&config.store_path) {
            Ok(store) => CryptoNix { store: Box::new(store), logger },
            Err(err) => Self::with_error(err),
        }
    }

    fn from_parsed_args(args: CryptoNixArgs) -> CryptoNix {
        match args.mode {
            CryptoNixMode::SledMode(sled) => Self::from_sled_config(&sled, args.logger),
            CryptoNixMode::ErrorMode(err) => Self::with_error(err),
        }
    }

    /// Parse the arguments and build a CryptoNix instance
    /// based on said arguments. If the arguments cannot be parsed,
    /// an instance will be constructed which will fail on every
    /// operation. CryptoNix, in general, uses this approach to allow
    /// enabling the plugin systemwide and not having nix crash
    /// if invoked w/o parameters.
    pub fn with_args(args: &str) -> CryptoNix {
        Self::from_parsed_args(CryptoNixArgs::from_args(args))
    }

    pub fn with_error(error: Error) -> CryptoNix {
        CryptoNix {
            store: Box::new(ErrorStore::from_error(error)),
            logger: Logger::dummy(),
        }
    }
}
