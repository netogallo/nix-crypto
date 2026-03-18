//! This module provides helper functions to assist in implementing
//! `IsCryptoStoreKey` and `IsOpensslPrivateKeyIdentity` for openssl
//! private key entities. The purpose of these helpers is to ensure
//! that the store key logic is defined once and reused across crates
//! that need to implement these traits for their own openssl private
//! key identity types.

use crate::error::Error;
use crate::openssl::pkey;
use crate::store::StoreHasher;

/// Computes the raw store key for an openssl private key identity.
///
/// This function is intended to be used as the implementation body of
/// `IsCryptoStoreKey::to_store_key_raw` for any type that identifies
/// an openssl private key by a `key_type` and `key_id` string pair.
///
/// # Arguments
///
/// * `key_type` - A string identifying the type of the key (e.g. `"rsa"`).
/// * `key_id` - A string uniquely identifying the key within its type.
/// * `hasher` - The `StoreHasher` instance provided by the store infrastructure.
///
/// # Returns
///
/// A `Vec<u8>` containing the raw bytes of the computed store key.
pub fn to_store_key_raw(key_type: &str, key_id: &str, mut hasher: StoreHasher) -> Vec<u8> {
    hasher.update(key_type.as_bytes());
    hasher.update(key_id.as_bytes());
    Vec::from(hasher.finish())
}

/// Serialises an openssl private key into raw bytes for storage.
///
/// This function is intended to be used as the implementation body of
/// `IsCryptoStoreKey::to_store_value_raw` for any type whose associated
/// value is a `pkey::Key`. The key is serialised as a PKCS8 PEM encoded
/// byte vector.
///
/// # Arguments
///
/// * `value` - A reference to the `pkey::Key` to be serialised.
///
/// # Returns
///
/// A `Result` containing the PEM encoded bytes of the key, or an `Error`
/// if serialisation fails.
pub fn to_store_value_raw(value: &pkey::Key) -> Result<Vec<u8>, Error> {
    pkey::Key::key_to_pem(value)
}

/// Deserialises an openssl private key from raw bytes retrieved from storage.
///
/// This function is intended to be used as the implementation body of
/// `IsCryptoStoreKey::from_store_value_raw` for any type whose associated
/// value is a `pkey::Key`. The bytes are expected to be a PKCS8 PEM encoded
/// private key.
///
/// # Arguments
///
/// * `bytes` - A reference to the raw bytes retrieved from the store.
///
/// # Returns
///
/// A `Result` containing the deserialised `pkey::Key`, or an `Error`
/// if deserialisation fails.
pub fn from_store_value_raw(bytes: &Vec<u8>) -> Result<pkey::Key, Error> {
    pkey::Key::key_from_pem(&bytes[..])
}
