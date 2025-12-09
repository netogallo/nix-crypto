use crate::foundations::{CryptoNix, CryptoStore, CryptoStoreExtensions, IsCryptoStoreKey, Error};
use crate::cxx_bridge::ffi::{OpensslPrivateKeyIdentity};
use openssl::sha;

pub mod pkey {
    use openssl::pkey::{Public, Private};
    use openssl::rsa;

    use crate::foundations::{Error};

    #[repr(u8)]
    pub enum Type {
        RsaKey = 0
    }

    impl From<u8> for Type {

        fn from(value: u8) -> Type {

            if(value == Type::RsaKey as u8) {
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

    pub enum Key {
       Rsa(rsa::Rsa<Private>) 
    }

    impl Key {

        pub fn new(key_type : Type) -> Result<Key, Error> {

            let rsa = rsa::Rsa::generate(4096)?;
            return Ok(Key::Rsa(rsa));
        }

        pub fn public_pem(self: &Self) -> Result<String, Error> {
            let pem_vec = match self {
                Key::Rsa(rsa) => rsa.public_key_to_pem()?
            };

            let result = String::from_utf8(pem_vec)?;
            Ok(result)
        }
    }

    impl TryFrom<&Vec<u8>> for Key {
        type Error = Error;

        fn try_from(value: &Vec<u8>) -> Result<Key, Error> {

            match Type::from(value[0]) {
                Type::RsaKey => {
                    let rsa_key = rsa::Rsa::private_key_from_pem(&value[1..])?;
                    Ok(Key::Rsa(rsa_key))
                },
                _ => Error::fail_with(format!("The value {} is not a known Openssl key type.", value[0]))
            }
        }
    }

    impl TryFrom<&Key> for Vec<u8> {
        type Error = Error;

        fn try_from(value: &Key) -> Result<Vec<u8>, Error> {

            match value {
                Key::Rsa(key) => {
                    let mut key_bytes = key.private_key_to_pem()?;
                    key_bytes.insert(0, u8::from(Type::RsaKey));
                    Ok(key_bytes)
                }
            }
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

impl CryptoNix {

    /// Generates an openssl private key of type 'key_type_str'. This
    /// key will be saved to the store.
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
}
