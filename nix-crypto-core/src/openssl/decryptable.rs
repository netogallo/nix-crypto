use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use openssl::symm::{encrypt, Cipher};
use openssl::rand::rand_bytes;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::error::Error;
use crate::foundations::{CryptoNix, IsCryptoStoreKeyDerivable};
use crate::store::{IsCryptoStoreKey, StoreHasher};
use crate::support::{Exportable};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Enum that lists all the key derivation schemes supported
/// by Nix Crypto for exporting decryptable credentials.
pub enum KeyDerivation {
    PBKDF2 = 0
}

impl KeyDerivation {

    pub fn from_string(value: &String) -> Result<KeyDerivation, Error> {
        match value.to_lowercase().as_str() {
            "pbkdf2" => Ok(KeyDerivation::PBKDF2),
            _ => Error::fail_with(
                format!("The given string '{}' is not a valid key derivation method.", value)
            )
        }
    }

    pub fn from_u8(value: u8) -> Result<KeyDerivation, Error> {

        if value == (KeyDerivation::PBKDF2 as u8) {
            Ok(KeyDerivation::PBKDF2)
        }
        else {
            Error::fail_with(format!("Cannot convert '{}' into a KeyDerivation", value))
        }
    }
}

// ============================================================================
// SymmetricKeyValue
// ============================================================================

/// The value stored in the `CryptoStore` for a symmetric key. Contains the
/// randomly generated secret, the key derivation scheme, and the iteration
/// count used for PBKDF2.
pub struct SymmetricKeyValue {
    pub random_secret: String,
    pub key_derivation: KeyDerivation,
    pub iterations: u32,
}

impl SymmetricKeyValue {
    /// Serialize to bytes as `<key_derivation>:<iterations>:<random_secret>`.
    fn to_bytes(&self) -> Vec<u8> {
        format!("{}:{}:{}", (self.key_derivation as u8).clone(), self.iterations, self.random_secret)
            .into_bytes()
    }

    /// Deserialize from bytes produced by `to_bytes`.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let s = std::str::from_utf8(bytes)?;

        // Split into at most 3 parts so the random_secret can itself contain ':'
        let mut parts = s.splitn(3, ':');

        let key_derivation_u8 = parts
            .next()
            .ok_or_else(|| Error::from_message("Missing key_derivation in SymmetricKeyValue".to_string()))?
            .to_string()
            .parse::<u8>()
            .map_err(|_| Error::from_message("Invalid key derivaiton for value.".to_string()))?;

        let key_derivation = KeyDerivation::from_u8(key_derivation_u8)?;

        let iterations_str = parts
            .next()
            .ok_or_else(|| Error::from_message("Missing iterations in SymmetricKeyValue".to_string()))?;

        let iterations = iterations_str
            .parse::<u32>()
            .map_err(|_| Error::from_message(format!("Invalid iterations value: {}", iterations_str)))?;

        let random_secret = parts
            .next()
            .ok_or_else(|| Error::from_message("Missing random_secret in SymmetricKeyValue".to_string()))?
            .to_string();

        Ok(SymmetricKeyValue { random_secret, key_derivation, iterations })
    }

    /// Derive a key and IV from the passphrase and salt using PBKDF2-HMAC-SHA256.
    ///
    /// For AES-128-CBC, `openssl enc -pbkdf2` derives `key_len + iv_len` = 32 bytes
    /// total from the passphrase, then splits them: first 16 bytes are the key,
    /// last 16 bytes are the IV. We replicate that behaviour here so that the
    /// output is compatible with `openssl enc -d -aes-128-cbc -pbkdf2`.
    fn derive_key_and_iv(&self, salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match self.key_derivation {
            KeyDerivation::PBKDF2 => {
                let mut key_and_iv = vec![0u8; 32];
                pbkdf2_hmac(
                    self.random_secret.as_bytes(),
                    salt,
                    self.iterations as usize,
                    MessageDigest::sha256(),
                    &mut key_and_iv,
                )?;
                let key = key_and_iv[..16].to_vec();
                let iv  = key_and_iv[16..].to_vec();
                Ok((key, iv))
            }
        }
    }
}

// ============================================================================
// IsOpensslSymmetricKeyIdentity
// ============================================================================

/// Identifies an OpenSSL symmetric key. Implementors provide the key identity,
/// derivation scheme, and PBKDF2 iteration count. The underlying
/// `SymmetricKeyValue` (including the random secret) is derived and stored
/// automatically.
pub trait IsOpensslSymmetricKeyIdentity {
    fn key_id(&self) -> &String;
    fn key_derivation(&self) -> &String;
    fn iterations(&self) -> u32;
}

/// A newtype wrapper around a reference to an arbitrary `IsOpensslSymmetricKeyIdentity`
/// instance. The `IsCrytpoStoreKeyDerivable` trait for symmetric key identites
/// is implemented through this type.
struct SymmetricKeyIdentity<'a, T: IsOpensslSymmetricKeyIdentity>(pub &'a T);

impl<'a, T : IsOpensslSymmetricKeyIdentity> IsCryptoStoreKey
for SymmetricKeyIdentity<'a, T> {
    type Value = SymmetricKeyValue;

    fn to_store_key_raw(&self, mut hasher: StoreHasher) -> Vec<u8> {
        let identity = self.0;
        let iterations = identity.iterations();
        hasher.update(identity.key_id().as_bytes());
        hasher.update(identity.key_derivation().as_bytes());
        hasher.update(&iterations.to_be_bytes());
        Vec::from(hasher.finish())
    }

    fn to_store_value_raw(value: &SymmetricKeyValue) -> Result<Vec<u8>, Error> {
        Ok(value.to_bytes())
    }

    fn from_store_value_raw(value: &Vec<u8>) -> Result<SymmetricKeyValue, Error> {
        SymmetricKeyValue::from_bytes(value)
    }
}

impl<'a, T: IsOpensslSymmetricKeyIdentity> IsCryptoStoreKeyDerivable
for SymmetricKeyIdentity<'a, T> {
    fn derive(&self) -> Result<SymmetricKeyValue, Error> {
        let mut random_bytes = vec![0u8; 16];
        rand_bytes(&mut random_bytes)?;
        let random_secret = STANDARD.encode(&random_bytes);

        Ok(SymmetricKeyValue {
            random_secret,
            key_derivation: KeyDerivation::from_string(&self.0.key_derivation())?,
            iterations: self.0.iterations(),
        })
    }
}

// ============================================================================
// EncryptionParams
// ============================================================================

/// Stores the salt used to encrypt a specific `(symmetric_key, credential)`
/// pair. By persisting this in the store we guarantee that calling
/// `export_decryptable` with the same key, credential, and store always
/// produces identical output.
///
/// The IV is not stored separately — it is derived deterministically from the
/// passphrase and salt by PBKDF2, exactly as `openssl enc -pbkdf2` does.
pub struct EncryptionParams {
    pub salt: Vec<u8>,
}

impl EncryptionParams {
    fn generate() -> Result<Self, Error> {
        let mut salt = vec![0u8; 8];
        rand_bytes(&mut salt)?;
        Ok(EncryptionParams { salt })
    }

    /// Serialize as the raw salt bytes.
    fn to_bytes(&self) -> Vec<u8> {
        self.salt.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::from_message("EncryptionParams bytes are empty".to_string()));
        }
        Ok(EncryptionParams { salt: bytes.to_vec() })
    }
}

/// The store key for `EncryptionParams`. It is derived by hashing the raw
/// store keys of both the symmetric key identity and the credential identity,
/// making it unique per `(key, credential)` pair.
struct EncryptionParamsKey<'a, TKey, TCred> {
    symmetric_key_identity: &'a TKey,
    credential_identity: &'a TCred,
}

impl<'a, TKey, TCred> EncryptionParamsKey<'a, TKey, TCred> {
    pub fn new(symmetric_key_identity: &'a TKey, credential_identity: &'a TCred) -> Self {
        EncryptionParamsKey { symmetric_key_identity, credential_identity }
    }
}

impl<'a, TKey, TCred> IsCryptoStoreKey
for EncryptionParamsKey<'a, TKey, TCred>
where TKey : IsCryptoStoreKey, TCred : IsCryptoStoreKey {
    type Value = EncryptionParams;

    fn to_store_key_raw(&self, mut hasher: StoreHasher) -> Vec<u8> {
        hasher.update(b"encryption_params");
        hasher.update_with_identity(self.symmetric_key_identity);
        hasher.update_with_identity(self.credential_identity);
        Vec::from(hasher.finish())
    }

    fn to_store_value_raw(value: &EncryptionParams) -> Result<Vec<u8>, Error> {
        Ok(value.to_bytes())
    }

    fn from_store_value_raw(value: &Vec<u8>) -> Result<EncryptionParams, Error> {
        EncryptionParams::from_bytes(value)
    }
}

impl<'a, TKey, TCred> IsCryptoStoreKeyDerivable for EncryptionParamsKey<'a, TKey, TCred>
where TKey : IsCryptoStoreKey, TCred : IsCryptoStoreKey {
    fn derive(&self) -> Result<EncryptionParams, Error> {
        EncryptionParams::generate()
    }
}

// ============================================================================
// Encryption helpers
// ============================================================================

/// Encrypt `plaintext` with AES-128-CBC and return a PEM-encoded string
/// compatible with `openssl enc -d -aes-128-cbc -pbkdf2`.
///
/// The key and IV are derived from the passphrase and salt using
/// PBKDF2-HMAC-SHA256, deriving 32 bytes total and splitting them into
/// a 16-byte key and a 16-byte IV — exactly as `openssl enc -pbkdf2` does.
///
/// The payload layout matches the OpenSSL `enc` format:
///   `Salted__` (8 bytes) | salt (8 bytes) | ciphertext
/// The whole payload is Base64-encoded and wrapped in a PEM envelope.
fn encrypt_to_pem(
    key: &SymmetricKeyValue,
    salt: &Vec<u8>,
    plaintext: &Vec<u8>
) -> Result<String, Error> {
    let (aes_key, iv) = key.derive_key_and_iv(salt)?;
    let cipher = Cipher::aes_128_cbc();
    let ciphertext = encrypt(cipher, &aes_key, Some(&iv), plaintext)?;

    let mut payload = Vec::new();
    payload.extend_from_slice(b"Salted__");
    payload.extend_from_slice(salt);
    payload.extend_from_slice(&ciphertext);

    let b64 = STANDARD.encode(&payload);

    // Wrap Base64 at 64 characters per line, as is standard for PEM
    let pem_body = b64
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n");

    Ok(pem_body)
}

// ============================================================================
// export_decryptable
// ============================================================================

/// Export a credential encrypted with a symmetric key, returning a
/// PEM-formatted string containing the AES-128-CBC encrypted credential,
/// compatible with `openssl enc -d -aes-128-cbc -pbkdf2`.
///
/// Calling this function multiple times with the same `key`, `credential`,
/// and store will always produce identical output, because the salt is
/// stored in the `CryptoStore` on the first call and reused thereafter.
pub fn export_decryptable<K, C>(
    crypto_nix: &CryptoNix,
    key: &K,
    credential: &C,
) -> Result<String, Error>
where
    K: IsOpensslSymmetricKeyIdentity,
    C: IsCryptoStoreKeyDerivable,
    C::Value: Exportable,
{
    // Step 1: Wrap the key in a SymmetricKeyIdentity and get or derive the
    // symmetric key value (random_secret, derivation, iterations).
    let symmetric_identity = SymmetricKeyIdentity(key);
    let symmetric_key_value = crypto_nix.get_or_derive(&symmetric_identity)?;

    // Step 2: Get or derive the credential value.
    let credential_value = crypto_nix.get_or_derive(credential)?;

    // Step 3: Get or derive the encryption params (salt) for this
    // (key, credential) pair. Using a unique salt per pair ensures that
    // encrypting the same credential with different keys produces different
    // ciphertext, preventing IV reuse.
    let encryption_params_key = EncryptionParamsKey::new(&symmetric_identity, credential);
    let encryption_params = crypto_nix.get_or_derive(&encryption_params_key)?;

    // Step 4: Export the credential to plaintext bytes.
    let plaintext = credential_value.export()?;

    // Step 5: Encrypt and return as PEM.
    encrypt_to_pem(
        &symmetric_key_value,
        &encryption_params.salt,
        &plaintext
    )
}

// ============================================================================
// get_symmetric_key_passphrase
// ============================================================================

/// Retrieve (or derive and store) the random passphrase for the symmetric key
/// identified by `key`. Returns the `random_secret` string which is the
/// passphrase used as input to the key derivation function.
///
/// Calling this function multiple times with the same `key` and store will
/// always return the same passphrase, because the `SymmetricKeyValue` is
/// stored on the first call and reused thereafter.
pub fn get_symmetric_key_passphrase<K: IsOpensslSymmetricKeyIdentity>(
    crypto_nix: &CryptoNix,
    key: &K,
) -> Result<String, Error> {
    let symmetric_identity = SymmetricKeyIdentity(key);
    let value = crypto_nix.get_or_derive(&symmetric_identity)?;
    Ok(value.random_secret)
}
