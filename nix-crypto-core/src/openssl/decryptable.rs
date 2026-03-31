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


    /// Derive a 128-bit AES key from a passphrase using the specified
    /// key derivation method.
    fn derive_aes_key(&self, salt: &[u8]) -> Result<Vec<u8>, Error> {

        match self.key_derivation {
            KeyDerivation::PBKDF2 => {
                let mut key = vec![0u8; 32];
                pbkdf2_hmac(
                    self.random_secret.as_bytes(),
                    salt,
                    self.iterations as usize,
                    MessageDigest::sha256(),
                    &mut key,
                )?;
                Ok(key)
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

const PEM_HEADER: &str = "-----BEGIN ENCRYPTED DATA-----";
const PEM_FOOTER: &str = "-----END ENCRYPTED DATA-----";

/// Encrypt `plaintext` with AES-128-CBC and return a PEM-encoded string.
///
/// The payload layout matches the OpenSSL `enc` format:
///   `Salted__` (8 bytes) | salt (8 bytes) | ciphertext
/// The whole payload is Base64-encoded and wrapped in a PEM envelope.
fn encrypt_to_pem(
    key: &SymmetricKeyValue,
    salt: &[u8],
    iv: &[u8],
    plaintext: &Vec<u8>
) -> Result<String, Error> {
    let key = key.derive_aes_key(salt)?;
    let cipher = Cipher::aes_128_cbc();
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
/// PEM-formatted string containing the AES-128-CBC encrypted credential.
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
    // Step 1: Wrap the key in a SymmetricKeyIdentity and get or derive the
    // symmetric key value (random_secret, derivation, iterations).
    let symmetric_identity = SymmetricKeyIdentity(key);
    let symmetric_key_value = crypto_nix.get_or_derive(&symmetric_identity)?;

    // Step 2: Get or derive the credential value
    let credential_value = crypto_nix.get_or_derive(credential)?;

    // Encription parameters are unique per key/credential combination. This
    // is important as the security of AES becomes weaker if the IV is
    // reused on different plaintext inputs.
    let encryption_params_key = EncryptionParamsKey::new(&symmetric_identity, credential);
    let encryption_params = crypto_nix.get_or_derive(&encryption_params_key)?;

    // Step 4: Export the credential to plaintext bytes
    let plaintext = credential_value.export()?;

    // Step 5: Encrypt and return as PEM
    encrypt_to_pem(
        &symmetric_key_value,
        &encryption_params.salt,
        &encryption_params.iv,
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
