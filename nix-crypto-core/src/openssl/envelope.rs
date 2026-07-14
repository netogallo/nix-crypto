use openssl::encrypt::Encrypter;
use crate::error::Error;
use openssl::pkey::{HasPublic, PKey};
use openssl::rsa::{Rsa, Padding};
use openssl::symm::{encrypt, Cipher};

use crate::envelope::*;

impl From<OpensslPadding> for Padding {

    fn from(value: OpensslPadding) -> Padding {

        match value {
            OpensslPadding::Pkcs1Oaep => Padding::PKCS1_OAEP
        }
    }
}

impl RsaKeySize {

    pub fn get_key_size<T : HasPublic>(key: &Rsa<T>) -> Option<Self> {

        match key.size() {
            // key.size() is in bytes, not bits
            512 => Some(RsaKeySize::Rsa4096),
            _ => None
        }
    }
}

impl AesKeySize {

    pub fn get_key_size(key: &[u8]) -> Option<Self> {

        match key.len() {
            32 => Some(Self::Aes256),
            16 => Some(Self::Aes128),
            _ => None
        }
    }
}

/// Encrypt the payload and produce an `Envelope` using the
/// given key and ciphertext. This function has hardcoded
/// choices for many of the encryption parameters which
/// get reflected on the envelope.
pub fn encrypt_with_rsa<T: HasPublic>(
    key: Rsa<T>, payload: &[u8]
) -> Result<Envelope, Error> {

    let key_size =
        RsaKeySize::get_key_size(&key)
        .ok_or::<Error>(format!("Unssported RSA key size: {}", key.size()).into())?;

    let key_ref = PKey::from_rsa(key)?;
    let mut encrypter = Encrypter::new(&key_ref)?;
    let padding = OpensslPadding::Pkcs1Oaep;
    encrypter.set_rsa_padding(padding.into())?;

    let buffer_len = encrypter.encrypt_len(&payload)?;
    let mut encrypted_payload = vec![0u8; buffer_len];
    let actual_len = encrypter.encrypt(&payload, &mut encrypted_payload)?;
    encrypted_payload.truncate(actual_len);

    Ok(
        Envelope::OpensslRsaEnvelope {
            rsa_key_size: key_size,
            rsa_padding: padding,
            rsa_ciphertext: encrypted_payload.into()
        }
    )
}

pub fn encrypt_with_pkey<T: HasPublic>(
    key: PKey<T>,
    payload: &[u8]
) -> Result<Envelope, Error> {

    if let Ok(rsa) = key.rsa() {
        return encrypt_with_rsa(rsa, payload);
    }

    let key_id = key.id();
    panic!("The given asymmetric key {key_id:?} is not supported by nix-crypto.")
}

pub fn select_aes_cipher(key_size: AesKeySize, mode: &AesMode) -> Result<Cipher, Error> {

    match (key_size, mode) {
        (AesKeySize::Aes256, AesMode::CBC) => Ok(Cipher::aes_256_cbc()),
        (AesKeySize::Aes128, AesMode::CBC) => Ok(Cipher::aes_128_cbc()),
        //spec => Err(format!("Unsopported AES mode {spec:?}").into())
    }
}

pub fn encrypt_with_aes_key(
    aes_key: &[u8],
    aes_iv: &[u8;16],
    payload: &[u8]
) -> Result<Envelope, Error> {

    let aes_key_size =
        AesKeySize::get_key_size(aes_key)
        .ok_or::<Error>(format!("Unsupported AES key size {}", aes_key.len()).into())?;
    let cipher = select_aes_cipher(aes_key_size, &AesMode::CBC)?;
    let aes_ciphertext = encrypt(cipher, aes_key, Some(aes_iv), payload)?;
    Ok(
        Envelope::OpensslAesEnvelope {
            aes_key_size,
            aes_ciphertext,
            aes_key_derivation: AesKeyDerivation::NoDerivation { aes_iv: aes_iv.clone() },
            aes_mode: AesMode::CBC,
        }
    )
}
