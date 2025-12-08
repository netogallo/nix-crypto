use crate::foundations::{CryptoNix, Error};
use crate::cxx_bridge::ffi::{OpensslPrivateKeyIdentity};

pub mod pkey {
    use openssl::pkey::{Public, Private};
    use openssl::rsa;

    use crate::foundations::{Error};

    pub enum Type {
        RsaKey
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
}

impl CryptoNix {

    /// Generates an openssl private key of type 'key_type_str'. This
    /// key will be saved to the store.
    pub fn openssl_private_key(
        &self,
        key_identity: &OpensslPrivateKeyIdentity
    ) -> Result<pkey::Key, Error> {

        let key_type = pkey::Type::try_from(&key_identity.key_type)?;

        //Todo: check if key already in store
        pkey::Key::new(key_type)
    }
}
