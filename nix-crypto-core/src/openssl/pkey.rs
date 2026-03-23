use openssl::pkey::{PKey, Public, Private};
use openssl::rsa;

// Imports from this crate
use crate::error::{Error};
use crate::foundations::{IsCryptoStoreKeyDerivable};
use crate::store::{IsCryptoStoreKey};

#[repr(u8)]
pub enum Type {
    RsaKey = 0
}

impl From<u8> for Type {

    fn from(value: u8) -> Type {

        if value == Type::RsaKey as u8 {
            return Type::RsaKey;
        }
        
        panic!("The value {} is not a vaild RSA key type", value)
    }
}

impl From<Type> for u8 {

    fn from(value: Type) -> u8 {
        value as u8
    }
}

impl TryFrom<&str> for Type {
    type Error = Error;

    fn try_from(value: &str) -> Result<Type, Error> {

        let error_message = format!("The value {value} is not a known openssl private key type.");

        match value {
            "rsa" => Ok(Type::RsaKey),
            _ => Error::fail_with(error_message)
        }
    }
}

impl TryFrom<&String> for Type {
    type Error = Error;

    fn try_from(value: &String) -> Result<Type, Error> {
        Type::try_from(value.as_str())
    }
}

/// CryptoNix wrapper type around 'PKey'. The main purpose
/// of this struct is to provide an API that can be used
/// in C++ code.
pub struct Key {
    pub pkey: PKey<Private>
}

impl Key {

    pub fn key_to_pem(&self) -> Result<Vec<u8>, Error> {
        let result = self.pkey.private_key_to_pem_pkcs8()?;
        Ok(result)
    }

    pub fn key_from_pem(pem_bytes: &[u8]) -> Result<Self, Error> {
        let pkey = PKey::private_key_from_pem(pem_bytes)?;
        Ok(Self::from_openssl_pkey(pkey))
    }

    pub fn from_openssl_pkey(pkey: PKey<Private>) -> Self {
        Key { pkey: pkey }
    }

    pub fn new(key_type : Type) -> Result<Key, Error> {

        match key_type {
            Type::RsaKey => {
                let rsa = rsa::Rsa::generate(4096)?;
                Ok(Key::from_openssl_pkey(PKey::from_rsa(rsa)?))
            }
        }
    }

    pub fn public_pem(self: &Self) -> Result<String, Error> {
        let pem = self.pkey.public_key_to_pem()?;
        let result = String::from_utf8(pem)?;
        Ok(result)
    }

    pub fn public_key(&self) -> Result<PKey<Public>, Error> {
        let pem = self.pkey.public_key_to_pem()?;
        let result = PKey::public_key_from_pem(&pem)?;
        Ok(result)
    }
}

/// This trait allows defining structs meant to be used as
/// identities for openssl private keys (in the context of
/// assymetric cryptography). They idea is that they contain
/// all the context needed to both uniquely reference a key
/// and generate the key if no reference currently exits.
pub trait IsOpensslPrivateKeyIdentity : IsCryptoStoreKey<Value = Key> {
    fn key_type(&self) -> &String;
    fn key_id(&self) -> &String;
}

impl<T : IsOpensslPrivateKeyIdentity> IsCryptoStoreKeyDerivable for T {

    fn derive(&self) -> Result<Key, Error> {
        let key_type = Type::try_from(self.key_type())?;
        Key::new(key_type)
    }
}
