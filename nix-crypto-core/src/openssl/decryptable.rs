use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use openssl::symm::{encrypt, Cipher};
use openssl::rand::rand_bytes;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::error::Error;
use crate::foundations::{CryptoNix, IsCryptoStoreKeyDerivable};
use crate::store::{IsCryptoStoreKey, StoreHasher};
use crate::openssl::pkey;

// ============================================================================
// Decryptable trait
// ============================================================================

/// A `Decryptable` value can be represented as a byte vector for the purpose
/// of encryption. This is the plaintext representation that will be encrypted,
/// not the encrypted representation itself.
pub trait Decryptable {
    fn export(&self) -> Result<Vec<u8>, Error>;
}

impl Decryptable for pkey::Key {
    fn export(&self) -> Result<Vec<u8>, Error> {
        self.key_to_pem()
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
    pub key_derivation: String,
    pub iterations: u32,
}

impl SymmetricKeyValue {
    /// Serialize to bytes as `<key_derivation>:<iterations>:<random_secret>`.
    fn to_bytes(&self) -> Vec<u8> {
        format!("{}:{}:{}", self.key_derivation, self.iterations, self.random_secret)
            .into_bytes()
    }

    /// Deserialize from bytes produced by `to_bytes`.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let s = std::str::from_utf8(bytes)?;

        // Split into at most 3 parts so the random_secret can itself contain ':'
        let mut parts = s.splitn(3, ':');

        let key_derivation = parts
            .next()
            .ok_or_else(|| Error::from_message("Missing key_derivation in SymmetricKeyValue".to_string()))?
            .to_string();

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
}

// ============================================================================
// IsOpensslSymmetricKeyIdentity
// ============================================================================

/// Identifies an OpenSSL symmetric key. Implementors provide the key identity,
/// derivation scheme, and PBKDF2 iteration count. The underlying
/// `SymmetricKeyValue` (including the random secret) is derived and stored
/// automatically.
pub trait IsOpensslSymmetricKeyIdentity : IsCryptoStoreKey<Value = SymmetricKeyValue> {
    fn key_id(&self) -> &String;
    fn key_derivation(&self) -> &String;
    fn iterations(&self) -> u32;
}

/// A newtype wrapper around a reference to any `IsOpensslSymmetricKeyIdentity`
/// implementor. This exists solely to provide a single, non-conflicting
/// `IsCryptoStoreKeyDerivable` impl for symmetric keys.
struct SymmetricKeyDerivable<'a, T: IsOpensslSymmetricKeyIdentity>(&'a T);

impl<'a, T: IsOpensslSymmetricKeyIdentity> SymmetricKeyDerivable<'a, T> {
    pub fn new(inner: &'a T) -> Self {
        SymmetricKeyDerivable(inner)
    }
}

impl<'a, T: IsOpensslSymmetricKeyIdentity> IsCryptoStoreKey for SymmetricKeyDerivable<'a, T> {
    type Value = SymmetricKeyValue;

    fn to_store_key_raw(&self, hasher: StoreHasher) -> Vec<u8> {
        self.0.to_store_key_raw(hasher)
    }

    fn to_store_value_raw(value: &SymmetricKeyValue) -> Result<Vec<u8>, Error> {
        T::to_store_value_raw(value)
    }

    fn from_store_value_raw(value: &Vec<u8>) -> Result<SymmetricKeyValue, Error> {
        T::from_store_value_raw(value)
    }
}

impl<'a, T: IsOpensslSymmetricKeyIdentity> IsCryptoStoreKeyDerivable for SymmetricKeyDerivable<'a, T> {
    fn derive(&self) -> Result<SymmetricKeyValue, Error> {
        let mut random_bytes = vec![0u8; 16];
        rand_bytes(&mut random_bytes)?;
        let random_secret = STANDARD.encode(&random_bytes);

        Ok(SymmetricKeyValue {
            random_secret,
            key_derivation: self.0.key_derivation().clone(),
            iterations: self.0.iterations(),
        })
    }
}

/// Serialization helpers for `SymmetricKeyValue`. These are free functions
/// rather than a blanket impl because Rust does not allow blanket impls of
/// `IsCryptoStoreKey` on trait objects.
pub fn symmetric_key_to_store_value_raw(value: &SymmetricKeyValue) -> Result<Vec<u8>, Error> {
    Ok(value.to_bytes())
}

pub fn symmetric_key_from_store_value_raw(value: &Vec<u8>) -> Result<SymmetricKeyValue, Error> {
    SymmetricKeyValue::from_bytes(value)
}

// ============================================================================
// EncryptionParams
// ============================================================================

/// Stores the salt and IV used to encrypt a specific `(symmetric_key, credential)`
/// pair. By persisting these in the store we guarantee that calling
/// `export_decryptable` with the same key, credential, and store always
/// produces identical output.
pub struct EncryptionParams {
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
}

impl EncryptionParams {
    fn generate() -> Result<Self, Error> {
        let mut salt = vec![0u8; 8];
        let mut iv = vec![0u8; 16];
        rand_bytes(&mut salt)?;
        rand_bytes(&mut iv)?;
        Ok(EncryptionParams { salt, iv })
    }

    /// Serialize as `<salt_len_1_byte><salt><iv>`.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.salt.len() as u8);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.iv);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::from_message("EncryptionParams bytes are empty".to_string()));
        }

        let salt_len = bytes[0] as usize;

        if bytes.len() < 1 + salt_len {
            return Err(Error::from_message("EncryptionParams bytes too short for salt".to_string()));
        }

        let salt = bytes[1..1 + salt_len].to_vec();
        let iv = bytes[1 + salt_len..].to_vec();

        Ok(EncryptionParams { salt, iv })
    }
}

/// The store key for `EncryptionParams`. It is derived by hashing the raw
/// store keys of both the symmetric key identity and the credential identity,
/// making it unique per `(key, credential)` pair.
pub struct EncryptionParamsKey {
    raw_key_key: Vec<u8>,
    raw_credential_key: Vec<u8>,
}

impl EncryptionParamsKey {
    pub fn new(raw_key_key: Vec<u8>, raw_credential_key: Vec<u8>) -> Self {
        EncryptionParamsKey { raw_key_key, raw_credential_key }
    }
}

impl IsCryptoStoreKey for EncryptionParamsKey {
    type Value = EncryptionParams;

    fn to_store_key_raw(&self, mut hasher: StoreHasher) -> Vec<u8> {
        hasher.update(b"encryption_params");
        hasher.update(&self.raw_key_key);
        hasher.update(&self.raw_credential_key);
        Vec::from(hasher.finish())
    }

    fn to_store_value_raw(value: &EncryptionParams) -> Result<Vec<u8>, Error> {
        Ok(value.to_bytes())
    }

    fn from_store_value_raw(value: &Vec<u8>) -> Result<EncryptionParams, Error> {
        EncryptionParams::from_bytes(value)
    }
}

impl IsCryptoStoreKeyDerivable for EncryptionParamsKey {
    fn derive(&self) -> Result<EncryptionParams, Error> {
        EncryptionParams::generate()
    }
}

// ============================================================================
// Encryption helpers
// ============================================================================

const PEM_HEADER: &str = "-----BEGIN ENCRYPTED DATA-----";
const PEM_FOOTER: &str = "-----END ENCRYPTED DATA-----";

/// Derive a 256-bit AES key from a passphrase using PBKDF2-SHA256.
fn derive_aes_key(passphrase: &str, salt: &[u8], iterations: u32) -> Result<Vec<u8>, Error> {
    let mut key = vec![0u8; 32];
    pbkdf2_hmac(
        passphrase.as_bytes(),
        salt,
        iterations as usize,
        MessageDigest::sha256(),
        &mut key,
    )?;
    Ok(key)
}

/// Encrypt `plaintext` with AES-256-CBC and return a PEM-encoded string.
///
/// The payload layout matches the OpenSSL `enc` format:
///   `Salted__` (8 bytes) | salt (8 bytes) | ciphertext
/// The whole payload is Base64-encoded and wrapped in a PEM envelope.
fn encrypt_to_pem(
    plaintext: &[u8],
    passphrase: &str,
    salt: &[u8],
    iv: &[u8],
    iterations: u32,
) -> Result<String, Error> {
    let key = derive_aes_key(passphrase, salt, iterations)?;
    let cipher = Cipher::aes_256_cbc();
    let ciphertext = encrypt(cipher, &key, Some(iv), plaintext)?;

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

    Ok(format!("{}\n{}\n{}", PEM_HEADER, pem_body, PEM_FOOTER))
}

// ============================================================================
// export_decryptable
// ============================================================================

/// Export a credential encrypted with a symmetric key, returning a
/// PEM-formatted string containing the AES-256-CBC encrypted credential.
///
/// Calling this function multiple times with the same `key`, `credential`,
/// and store will always produce identical output, because the salt and IV
/// are stored in the `CryptoStore` on the first call and reused thereafter.
pub fn export_decryptable<K, C>(
    crypto_nix: &CryptoNix,
    key: &K,
    credential: &C,
) -> Result<String, Error>
where
    K: IsOpensslSymmetricKeyIdentity,
    C: IsCryptoStoreKeyDerivable,
    C::Value: Decryptable,
{
    // Step 1: Wrap the key in a SymmetricKeyDerivable and get or derive the
    // symmetric key value (random_secret, derivation, iterations).
    let derivable_key = SymmetricKeyDerivable::new(key);
    let symmetric_key_value = crypto_nix.get_or_derive(&derivable_key)?;

    // Step 2: Get or derive the credential value
    let credential_value = crypto_nix.get_or_derive(credential)?;

    // Step 3: Build the EncryptionParamsKey from the raw store keys of both
    // the symmetric key and the credential, then get or derive the params.
    let raw_key_key = crypto_nix.to_store_key_raw_pub(key);
    let raw_credential_key = crypto_nix.to_store_key_raw_pub(credential);
    let encryption_params_key = EncryptionParamsKey::new(raw_key_key, raw_credential_key);
    let encryption_params = crypto_nix.get_or_derive(&encryption_params_key)?;

    // Step 4: Export the credential to plaintext bytes
    let plaintext = credential_value.export()?;

    // Step 5: Encrypt and return as PEM
    encrypt_to_pem(
        &plaintext,
        &symmetric_key_value.random_secret,
        &encryption_params.salt,
        &encryption_params.iv,
        symmetric_key_value.iterations,
    )
}
