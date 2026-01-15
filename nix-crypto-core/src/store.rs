use openssl::sha::Sha256;

use crate::error::*;

pub struct StoreHasher(Sha256);

impl StoreHasher {
    pub fn init(salt: &[u8]) -> Self {
        let mut sha256 = Sha256::new();
        sha256.update(salt);
        StoreHasher(sha256)
    }

    pub fn update(&mut self, buf: &[u8]) {
        self.0.update(buf);
    }

    pub fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

/// This trait servs to tag values that can be used as a key for
/// the 'CryptoStore'. Must have an asociated value, which  must
/// be unique for every instance of this trait. This trait specifies
/// how the key and the value are to be serialized and deserialized
/// when saved/fetched from the store.
pub trait IsCryptoStoreKey {
    type Value;
    fn to_store_key_raw(&self, hasher: StoreHasher) -> Vec<u8>;
    fn to_store_value_raw(value: &Self::Value) -> Result<Vec<u8>, Error>;
    fn from_store_value_raw(value: &Vec<u8>) -> Result<Self::Value, Error>;
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

/// The 'ErrorStore' represents a store that will fail
/// on every operation. This is meant to avoid the
/// case of Nix hard-crashing if the store cannot
/// be initialized. Instead, functions using the
/// store will produce an error.
pub struct ErrorStore {
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
pub struct SledStore {
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
