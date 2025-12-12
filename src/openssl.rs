use openssl::pkey::{Public, Private, PKey};
use openssl::sha;
use openssl::x509::{X509, X509Builder};

use crate::error::{Error};
use crate::foundations::{CryptoNix, CryptoStore, CryptoStoreExtensions, IsCryptoStoreKey};
use crate::cxx_bridge::ffi::{OpensslPrivateKeyIdentity, X509BuildParams};
use crate::cxx_support::{CxxTryOption};

pub mod pkey {
    use openssl::pkey::{PKey, PKeyRef, Public, Private};
    use openssl::rsa;

    use crate::error::{Error};

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
        pkey: PKey<Private>
    }

    impl Key {

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
            let result = PKey::public_key_from_raw_bytes(
                &self.pkey.raw_public_key()?[..],
                self.pkey.id()
            )?;
            Ok(result)
        }
    }

    impl TryFrom<&Vec<u8>> for Key {
        type Error = Error;

        fn try_from(value: &Vec<u8>) -> Result<Key, Error> {
            let result = Key::from_openssl_pkey(
                PKey::private_key_from_pem(&value[..])?
            );
            Ok(result)
        }
    }

    impl TryFrom<&Key> for Vec<u8> {
        type Error = Error;

        fn try_from(value: &Key) -> Result<Vec<u8>, Error> {
            let result = value.pkey.private_key_to_pem_pkcs8()?;
            Ok(result)
        }
    }
}

impl IsCryptoStoreKey for OpensslPrivateKeyIdentity {

    fn into_crypto_store_key(&self, salt: &[u8]) -> Vec<u8> {
        let mut hasher = sha::Sha256::new();
        hasher.update(salt);
        hasher.update(self.key_type.as_bytes());
        hasher.update(self.key_id.as_bytes());
        Vec::from(hasher.finish())
    }
}

impl X509BuildParams {

    pub fn get_subject_public_key(&self) -> Result<Option<PKey<Public>>, Error> {

        let key_str = self.subject_public_key.try_option()?;

        match key_str {
            Some(pem) => {
                let result = PKey::public_key_from_pem(pem.as_bytes())?;
                Ok(Some(result))
            },
            None => Ok(None)
        }
    }
}

impl CryptoNix {

    /// Get the Openssl private key which corresponds to the
    /// given 'OpensslPrivateKeyIdentity'. If there is no key
    /// associated with that identity, a fresh key will be
    /// generated and saved to the store.
    pub fn openssl_private_key(
        &self,
        key_identity: &OpensslPrivateKeyIdentity
    ) -> Result<pkey::Key, Error> {


        let key_type = pkey::Type::try_from(&key_identity.key_type)?;
        match self.get(key_identity)? {
            Some(key) => Ok(key),
            None => {
                let key = pkey::Key::new(key_type)?;
                self.put(key_identity, &key)?;
                Ok(key)
            }
        }
    }

    pub fn openssl_x509_cert(
        &self,
        params: &X509BuildParams
    ) -> Result<X509, Error> {

        let signing_key = self.openssl_private_key(&params.signing_private_key_identity)?;

        /*
        let subject_key: PKey<Public> = match params.get_subject_public_key()? {

            // Subject has been explicitly provided
            Some(sub) => &sub,

            // No subject provided, certificate will be self-sigend
            None => &signing_key.pkey.
        };
        */

        panic!("not implementedd")
    }
}
