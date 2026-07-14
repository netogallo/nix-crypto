//use base64::engine::general_purpose::STANDARD;
//use base64::Engine;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use serde::{Serialize, Deserialize};
use serde_json::{from_slice, to_vec};

use crate::error::Error;
use crate::foundations::{CryptoNix, IsCryptoStoreKeyDerivable};
use crate::store::{IsCryptoStoreKey, StoreHasher};
use crate::support::{Exportable};
use crate::envelope::{Envelope};
use crate::openssl::envelope::{encrypt_with_pkey, encrypt_with_aes_key};
use crate::openssl::pkey::{IsOpensslPrivateKeyIdentity, Key, OpensslPrivateKeyIdentityWrapper};

/// To encrypte large payloads using asymmetric encryption,
/// a random symmetric key is generated to encrypt the
/// payload. The symmetric key then gets encrypted with the
/// asymmetric public key.
#[derive(Clone, Serialize, Deserialize)]
pub struct AsymmetricEncryptionResult {
    pub encrypted_ephermeral_key: Envelope,
    pub encrypted_payload: Envelope
}

struct AsymmetricEncryptionRequest<Cred>
where
    Cred: IsCryptoStoreKeyDerivable,
    Cred::Value: Exportable,
{
    store_key: Vec<u8>,
    pkey: Key,
    credential: Cred::Value,
}

static IV_SIZE : usize = 16;

impl<C> IsCryptoStoreKey for AsymmetricEncryptionRequest<C>
where
    C: IsCryptoStoreKeyDerivable,
    C::Value: Exportable,
{
    type Value = AsymmetricEncryptionResult;

    fn to_store_key_raw(&self, _hasher: StoreHasher) -> Vec<u8> {
        self.store_key.clone()
    }

    fn to_store_value_raw(value: &Self::Value) -> Result<Vec<u8>, Error> {
        let result = to_vec(value)?;
        Ok(result)
    }

    fn from_store_value_raw(value: &Vec<u8>) -> Result<Self::Value, Error> {
        let result = from_slice(value.as_slice())?;
        Ok(result)
    }
}

impl<C> IsCryptoStoreKeyDerivable for AsymmetricEncryptionRequest<C>
where
    C: IsCryptoStoreKeyDerivable,
    C::Value: Exportable,
{
    fn derive(&self) -> Result<AsymmetricEncryptionResult, Error> {
        // Export the credential to bytes.
        let credential_bytes = self.credential.export()?;

        // Generate a random 256-bit (32 byte) AES symmetric key.
        let mut sym_key = vec![0u8; 32];
        rand_bytes(&mut sym_key)?;

        // Generate a random 128-bit (16 byte) IV for AES-256-CBC.
        let mut iv = [0u8; IV_SIZE];
        rand_bytes(&mut iv)?;

        // Select the Asymmetric key that will be used to encrypt
        // the ephemeral symmetric key.
        let pkey_ref = PKey::from_rsa(self.pkey.pkey.rsa()?)?;

        // Create an encrypted envelope containing the encrypted ephemeral
        // symmetric key
        let encrypted_ephermeral_key = encrypt_with_pkey(pkey_ref, &sym_key)?;

        // Create an encrypted envelope containing the credenital. This
        // envelope is encrypted using the ephemeral symmetric key.
        let encrypted_payload = encrypt_with_aes_key(&sym_key, &iv, &credential_bytes)?;

        Ok(AsymmetricEncryptionResult {
            encrypted_ephermeral_key,
            encrypted_payload
        })
    }
}

pub fn export_encrypted<K, C>(
    crypto_nix: &CryptoNix,
    key: &K,
    credential: &C,
) -> Result<AsymmetricEncryptionResult, Error>
where
    K: IsOpensslPrivateKeyIdentity,
    C: IsCryptoStoreKeyDerivable,
    C::Value: Exportable,
{
    // Resolve the asymmetric key using get_or_derive.
    let pkey_wrapper = OpensslPrivateKeyIdentityWrapper(key);
    let pkey = crypto_nix.get_or_derive(&pkey_wrapper)?;

    // Resolve the credential using get_or_derive.
    let resolved_credential = crypto_nix.get_or_derive(credential)?;

    // Compute the store key by hashing the asymmetric key identity and
    // credential identity together using StoreHasher.
    let mut hasher = StoreHasher::init(crypto_nix.salt());
    hasher.update(b"asymmetric_encryption");
    hasher.update_with_identity(&pkey_wrapper);
    hasher.update_with_identity(credential);
    let store_key = Vec::from(hasher.finish());

    // Construct the AsymmetricEncryptionKey struct.
    let asym_enc_key = AsymmetricEncryptionRequest::<C> {
        store_key,
        pkey,
        credential: resolved_credential,
    };

    // Get or compute the AsymmetricEncryptionResult.
    crypto_nix.get_or_derive(&asym_enc_key)
}
