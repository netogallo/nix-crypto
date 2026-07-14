use serde::{Serialize, Deserialize};

/// The set of openssl padding schemes supported
/// by nix-crypto
#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum OpensslPadding {
    Pkcs1Oaep
}

/// This enum specifies the RSA key sizes supported
/// by nix-crypto.
#[derive(Copy, Clone, Serialize, Deserialize)]
#[repr(u16)]
pub enum RsaKeySize {
    Rsa4096 = 4096
}

impl From<&RsaKeySize> for i64 {

    fn from(key_size: &RsaKeySize) -> i64 {
        key_size.clone() as i64
    }
}

/// This enum specifies the AES key sizes supported
/// by nix-crypto
#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
#[repr(u16)]
pub enum AesKeySize {
    Aes128 = 128,
    Aes256 = 256
}

impl From<&AesKeySize> for i64 {

    fn from(key_size: &AesKeySize) -> i64 {
        key_size.clone() as i64
    }
}

/// This enum specifies the AES modes supported
/// by nix-crypto
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum AesMode {
    CBC
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AesKeyDerivation {
    NoDerivation { aes_iv: [u8; 16] },
    Pbkdf2Derivation {
        aes_pbkdf2_salt: [u8; 16],
        aes_pbkdf2_rounds: u32
    }
}

/// An envelope is a data structure which holds encrypted
/// ciphertext as well as metadata indicating what were
/// the parameters to encrypt said text. By providing a
/// decryption key, it should be possible to determine
/// the decryption method needed to recover the plaintext
#[derive(Clone, Serialize, Deserialize)]
pub enum Envelope {
    OpensslRsaEnvelope {
        rsa_key_size: RsaKeySize,
        rsa_padding: OpensslPadding,
        rsa_ciphertext: Vec<u8>
    },
    OpensslAesEnvelope {
        aes_key_size: AesKeySize,
        aes_key_derivation: AesKeyDerivation,
        aes_mode: AesMode,
        aes_ciphertext: Vec<u8>
    },
}
