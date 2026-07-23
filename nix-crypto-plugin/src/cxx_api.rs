use cxx::{CxxString};
use std::boxed::{Box};

// Imports from sister crates
use nix_crypto_core::error::{Error};
use nix_crypto_core::foundations::{CryptoNix};
use nix_crypto_core::openssl::ffi;
use nix_crypto_core::openssl::pkey::OpensslPrivateKeyIdentityWrapper;
use nix_crypto_core::openssl::decryptable::{export_decryptable, IsOpensslSymmetricKeyIdentity};

// Imports from this crate
use crate::cxx_bridge::ffi::*;
use crate::cxx_support::*;
use crate::cxx_api::data::{CxxNixAttrs};

pub mod data;

pub fn rust_add(left: u64, right: u64) -> u64 {
    left + right
}

/// CXX wrapper type for "CryptoNix". This is meant to expose
/// the nix-crypto interface that will be accesible in C++
pub struct CxxNixCrypto(CryptoNix);

/// Create a 'CxxNixCrypto' instance. This function accepts
/// a 'CxxString' with the parameters for nix-crypto. It
/// will process the parameters as appropiate and construct
/// an instance of cryptonix configured with the given parameters.
pub fn nix_crypto_with_settings(params: &CxxString) -> Box<CxxNixCrypto> {

    let utf8_error = "Unexpected error in CryptoNix. The arguments supplied are not a valid utf-8 string. Please report this bug!";

    let nix_crypto = match params.to_str() {
        Ok(rust_params) => {
            CryptoNix::with_args(rust_params)
        },
        Err(_err) =>
            CryptoNix::with_error(Error::CxxError(utf8_error.to_string()))
    };
    Box::new(CxxNixCrypto(nix_crypto))
}

pub struct CxxOpensslPrivateKey(nix_crypto_core::openssl::pkey::Key);

impl ffi::IsOpensslPrivateKeyIdentity for OpensslPrivateKeyIdentity {

    fn key_type(&self) -> &String {
        &self.key_type
    }

    fn key_id(&self) -> &String {
        &self.key_id
    }
}

impl IsOpensslSymmetricKeyIdentity for OpensslSymmetricKeyIdentity {

    fn key_id(&self) -> &String {
        &self.key_id
    }

    fn key_derivation(&self) -> &String {
        &self.key_derivation
    }

    fn iterations(&self) -> u32 {
        self.iterations
    }
}

impl CxxOpensslPrivateKey {
    pub fn public_pem(&self) -> Result<String, Error> {
        self.0.public_pem()
    }
}

impl ffi::IsX509NameItem for X509NameItem {
    fn entry_name(&self) -> &String {
        &self.entry_name
    }

    fn entry_value(&self) -> &String {
        &self.entry_value
    }
}

impl ffi::IsX509KeyUsage for X509KeyUsage {

    fn critical(&self) -> bool {
        self.critical
    }

    fn key_cert_sign(&self) -> bool {
        self.key_cert_sign
    }

    fn crl_sign(&self) -> bool {
        self.crl_sign
    }

    fn digital_signature(&self) -> bool {
        self.digital_signature
    }

    fn key_encipherment(&self) -> bool {
        self.key_encipherment
    }
}

impl ffi::IsX509BasicConstraints for X509BasicConstraints {
    fn critical(&self) -> bool {
        self.critical
    }

    fn ca(&self) -> bool {
        self.ca
    }
}

impl ffi::IsX509BuildParams for X509BuildParams {
    type PrivateKeyIdentity = OpensslPrivateKeyIdentity;
    type NameItem = X509NameItem;
    type KeyUsage = X509KeyUsage;
    type BasicConstraints = X509BasicConstraints;

    fn subject_public_key(&self) -> Option<&String> {
        self.subject_public_key.try_option().unwrap()
    }

    fn signing_private_key_identity(&self) -> &OpensslPrivateKeyIdentity {
        &self.signing_private_key_identity
    }

    fn issuer_name(&self) -> &Vec<X509NameItem> {
        &self.issuer_name
    }

    fn subject_name(&self) -> &Vec<X509NameItem> {
        &self.subject_name
    }

    fn serial(&self) -> u32 {
        self.serial
    }

    fn start_date(&self) -> &String {
        &self.start_date
    }

    fn expiry_date(&self) -> &String {
        &self.expiry_date
    }

    fn extension_key_usage(&self) -> Option<&X509KeyUsage> {
        self.extension_key_usage.try_option().unwrap()
    }

    fn extension_basic_constraints(&self) -> Option<&X509BasicConstraints> {
        self.extension_basic_constraints.try_option().unwrap()
    }
}


pub struct CxxOpensslX509Certificate(nix_crypto_core::openssl::x509::X509Certificate);

impl CxxOpensslX509Certificate {
    pub fn public_pem(&self) -> Result<String, Error> {
        self.0.public_pem()
    }
}

impl CxxNixCrypto {

    pub fn cxx_openssl_private_key(self: &CxxNixCrypto, key_identity: OpensslPrivateKeyIdentity) -> Result<Box<CxxOpensslPrivateKey>, Error> {

        let key = self.0.openssl_private_key(&key_identity)?;
        Ok(Box::new(CxxOpensslPrivateKey(key)))
    }

    pub fn cxx_openssl_x509_certificate(&self, args: X509BuildParams) -> Result<Box<CxxOpensslX509Certificate>, Error> {
        let result = self.0.openssl_x509_certificate(&args)?;
        Ok(Box::new(CxxOpensslX509Certificate(result)))
    }

    /// Export an openssl private key credential encrypted with the given symmetric key,
    /// returning a PEM-formatted string containing the AES-128-CBC encrypted private key.
    ///
    /// This is a monomorphic wrapper around `export_decryptable` for the
    /// `OpensslPrivateKeyIdentity` credential type, making it callable from C++.
    pub fn cxx_export_decryptable_openssl_pkey(
        &self,
        symmetric_key: OpensslSymmetricKeyIdentity,
        credential: OpensslPrivateKeyIdentity,
    ) -> Result<String, Error> {
        export_decryptable(
            &self.0,
            &symmetric_key,
            &OpensslPrivateKeyIdentityWrapper(&credential),
        )
    }

    /// Export an openssl private key credential encrypted with the given asymmetric key,
    /// returning a PEM-formatted string containing the RSA-OAEP encrypted symmetric key
    /// and the AES-256-CBC encrypted credential.
    ///
    /// This is a monomorphic wrapper around `export_encrypted` for the
    /// `OpensslPrivateKeyIdentity` type on both type arguments, making it callable from C++.
    pub fn cxx_export_encrypted_openssl_pkey_pkey<'a>(
        &self,
        key: OpensslPrivateKeyIdentity,
        credential: OpensslPrivateKeyIdentity,
    ) -> Result<Box<CxxNixAttrs<'a>>, Error> {
        let result = self.0.export_encrypted(
            &key,
            &OpensslPrivateKeyIdentityWrapper(&credential),
        )?;
        Ok(Box::new(CxxNixAttrs::new(result)))
    }
}
