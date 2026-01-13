use openssl::asn1::{Asn1Time};
use openssl::bn::{BigNum};
use openssl::hash::{MessageDigest};
use openssl::pkey::{Public, Private, PKey};
use openssl::sha;
use openssl::x509::{X509, X509Extension, X509Name, X509NameBuilder
    , X509Builder};
use openssl::x509::extension::{AuthorityKeyIdentifier, KeyUsage, BasicConstraints
    , SubjectKeyIdentifier};

use time::{UtcDateTime};
use time::format_description::well_known::{Rfc3339};

use crate::error::{Error};
use crate::foundations::{CryptoNix};
use crate::cxx_support::{CxxTryOption};
use crate::store::{IsCryptoStoreKey};

pub mod ffi {

    pub trait IsOpensslPrivateKeyIdentity {
        fn key_type(&self) -> String;
        fn key_id(&self) -> String;
    }

    pub trait IsX509NameItem {
        fn entry_name(&self) -> String;
        fn entry_value(&self) -> String;
    }

    pub trait IsX509KeyUsage {
        fn critical(&self) -> bool;
        fn key_cert_sign(&self) -> bool;
        fn crl_sign(&self) -> bool;
    }

    pub trait IsX509BasicConstraints {
        fn critical(&self) -> bool; 
        fn ca(&self) -> bool;
    }

    pub trait IsX509BuildParams {
        type PrivateKeyIdentity : IsOpensslPrivateKeyIdentity;
        type NameItem : IsX509NameItem;
        type KeyUsage : IsX509KeyUsage;
        type BasicConstraints : IsX509BasicConstraints;

        fn subject_public_key(&self) -> Option<String>;
        fn signing_private_key_identity(&self) -> Self::PrivateKeyIdentity;
        fn issuer_name(&self) -> Vec<Self::NameItem>;
        fn subject_name(&self) -> Vec<Self::NameItem>;
        fn start_date(&self) -> String;
        fn expiry_date(&self) -> String;
        fn extension_key_usage(&self) -> Option<Self::KeyUsage>;
        fn extension_basic_constraints(&self) -> Option<Self::BasicConstraints>;
    }

    fn name_from_entries(entries: &Vec<T>) -> Result<X509Name, Error>
    where T : IsX509NameItem {
        let mut builder = X509NameBuilder::new()?;
        for entry in entries.iter() {
            builder.append_entry_by_text(&entry.entry_name, &entry.entry_value)?;
        }
    
        Ok(builder.build())
    }

    fn parse_date_rfc3339(date: &str) -> Result<Asn1Time, Error> {
        let utc = UtcDateTime::parse(date, &Rfc3339)?;
        Ok(Asn1Time::from_unix(utc.unix_timestamp())?)
    }

    impl <T: X509KeyUsage> T {
    
        pub fn build(&self) -> Result<X509Extension, Error> {
    
            let mut builder = KeyUsage::new();
    
            if self.critical {
                builder.critical();
            }
    
            if self.key_cert_sign {
                builder.key_cert_sign();
            }
    
            if self.crl_sign {
                builder.crl_sign();
            }
    
            Ok(builder.build()?)
        }
    }

    impl ffi::X509BasicConstraints {
    
        pub fn build(&self) -> Result<X509Extension, Error> {
    
            let mut builder = BasicConstraints::new();
    
            if self.critical {
                builder.critical();
            }
    
            if self.ca {
                builder.ca();
            }
    
            Ok(builder.build()?)
        }
    }

    impl<T : IsX509BuildParams> T {
    
        pub fn get_subject_public_key(&self) -> Result<Option<PKey<Public>>, Error> {
    
            match self.subject_public_key() {
                Some(pem) => {
                    let result = PKey::public_key_from_pem(pem.as_bytes())?;
                    Ok(Some(result))
                },
                None => Ok(None)
            }
        }
    
        pub fn build_issuer_name(&self) -> Result<X509Name, Error> {
            name_from_entries(&self.issuer_name())
        }
    
        pub fn build_subject_name(&self) -> Result<X509Name, Error> {
            name_from_entries(&self.subject_name())
        }
    
        pub fn start_date_as_asn1(&self) -> Result<Asn1Time, Error> {
            parse_date_rfc3339(&self.start_date())
        }
    
        pub fn expiry_date_as_asn1(&self) -> Result<Asn1Time, Error> {
            parse_date_3339(&self.expiry_date())
        }
    
        /// Convert the key usage declarations specified in the CXX struct
        /// into a 'X509Extension' which can be applied when building
        /// a 'X509' certificate.
        pub fn build_key_usage_ext(&self) -> Result<Option<X509Extension>, Error> {
            self.extension_key_usage()
                .map(|e| e.build())
                .transpose()
        }
    
        /// Convert the basic constraints that have been declared in the
        /// CXX call into a 'X509Extension', which can be applied when building
        /// a 'X509' certificate.
        pub fn build_basic_constraints_ext(&self) -> Result<Option<X509Extension>, Error> {
            self.extension_basic_constraints()
                .map(|e| e.build())
                .transpose()
        }
    }
}

pub mod pkey {
    use openssl::pkey::{PKey, PKeyRef, Public, Private};
    use openssl::rsa;

    use crate::error::{Error};
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
}

pub mod x509 {
    use openssl::x509::{X509};

    use crate::error::{Error};

    /// This is a wrapper tipe for the 'X509' type defined in the
    /// 'openssl' crate. The main purpose of this type is to
    /// expose methods which can be invoked from C++ code.
    pub struct X509Certificate {
        pub certificate: X509
    }

    impl X509Certificate {

        pub fn new(cert: X509) -> Self {
            X509Certificate { certificate: cert }
        }

        pub fn public_pem(&self) -> Result<String, Error> {
            let pem = self.certificate.to_pem()?;
            let result = String::from_utf8(pem)?;
            Ok(result)
        }
    }
}

impl CryptoNix {

    /// Get the Openssl private key which corresponds to the
    /// given 'OpensslPrivateKeyIdentity'. If there is no key
    /// associated with that identity, a fresh key will be
    /// generated and saved to the store.
    pub fn openssl_private_key<T>(
        &self,
        key_identity: &T
    ) Result<T as ffi::IsCryptoStoreKey>::Value, Error> 
    where T : ffi::IsCryptoStoreKey -> {


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

    /// Construct an X509 certificate. This function accepts a 'X50BuildParams'
    /// which describe how the certificate is to be built in the context of
    /// nix-crypto.
    pub fn openssl_x509_certificate<T>(
        &self,
        params: &T
    ) -> Result<x509::X509Certificate, Error>
    where T : IsX509BuildParams {

        let signing_key = self.openssl_private_key(&params.signing_private_key_identity)?;

        let subject_key: PKey<Public> = match params.get_subject_public_key()? {

            // Subject has been explicitly provided
            Some(sub) => sub,

            // No subject provided, certificate will be self-sigend
            None => signing_key.public_key()?
        };

        let mut builder = X509Builder::new()?;
        let issuer_name = params.build_issuer_name()?;
        let subject_name = params.build_subject_name()?;

        builder.set_pubkey(&subject_key)?;
        builder.set_issuer_name(&issuer_name)?;
        builder.set_subject_name(&subject_name)?;

        let serial = BigNum::from_u32(params.serial)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;

        let start_date = params.start_date_as_asn1()?;
        let expiry_date = params.expiry_date_as_asn1()?;
        builder.set_not_before(&start_date)?;
        builder.set_not_after(&expiry_date)?;

        params.build_key_usage_ext()?
            .map(|e| builder.append_extension(e))
            .transpose()?;

        params.build_basic_constraints_ext()?
            .map(|e| builder.append_extension(e))
            .transpose()?;

        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?,
        )?;

        builder.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&builder.x509v3_context(None, None))?,
        )?;

        builder.sign(&signing_key.pkey, MessageDigest::sha256())?;

        Ok(x509::X509Certificate::new(builder.build()))
    }
}
