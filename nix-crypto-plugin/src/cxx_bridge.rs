// This module will get parsed by the cxx:builder. Avoid anything
// other than definitions strictly needed for the C++ bridge, as
// any changes here incurr long re-compilation. For utilities
// related to the CXX bridge, use the cxx_support module. Function
// implementations for the functions in this module should be placed
// in cxx_api
use cxx::{CxxString, UniquePtr};

use nix_crypto_core::error::{Error};
use nix_crypto_core::foundations::{CryptoNix};
use nix_crypto_core::openssl::ffi::*;

use crate::cxx_api::*;

#[cxx::bridge]
pub mod ffi {
    /// This struct defines a key identity for openssl. An identity
    /// is simply an object that is able to reference a particular key.
    /// In order to avoid exposing private keys in nix code (so they cannot
    /// land in the store), nix code will provide an identity (rather than
    /// the private key) to indicate what key is to be used to sign/encrypt
    /// values.
    pub struct OpensslPrivateKeyIdentity {
        pub key_type: String,
        pub key_id : String
    }

    pub struct X509NameItem {
        pub entry_name: String,
        pub entry_value: String
    }

    pub struct X509KeyUsage {
        pub critical: bool,
        pub key_cert_sign: bool,
        pub crl_sign: bool
    }

    pub struct X509BasicConstraints {
        pub critical: bool,
        pub ca: bool
    }

    /// This struct identifies a X509Certificate. Note that
    /// each parameter has additional constraints. The expectation
    /// is that the same set of parameters will result in the same
    /// certificate accross multiple invocations.
    pub struct X509BuildParams {
        /// The public key asociated to the private key of
        /// the certificate's subject. The value should be one
        /// of the following:
        /// * A Vec containing a *single* element which must be
        ///   the key as a PEM encoded String
        /// * An *empty* Vec. In this case, the certificate will
        ///   be a "self-signed" certificate, meaning the public
        ///   key associated to the signing key will be the
        ///   certificate's subject's private key.
        ///
        /// Todo: Ideally, this should be an 'Option<String>' but
        /// it seems that is not supported by the CXX crate.
        pub subject_public_key: Vec<String>,
        /// The private key that will be used to sign the certificate.
        pub signing_private_key_identity: OpensslPrivateKeyIdentity,
        /// The name components of the certificate. Note that for
        /// identity purposes, the order in which they are defined
        /// does not matter. Furthermore, duplicate keys are not
        /// allowed.
        pub issuer_name: Vec<X509NameItem>,
        pub subject_name: Vec<X509NameItem>,
        /// The serial of the certificate
        pub serial: u32,
        /// The starting day of the certificate's validity. This must
        /// be a string in the "RFC3339" format. Note that this is required
        /// as "now" cannot be used to mantain the function pure.
        pub start_date: String,
        /// The expiry date of the certificate. This must
        /// be a string in the "RFC3339" format. Note that this is required
        /// as "now" cannot be used to mantain the function pure.
        pub expiry_date: String,
        /// This controls the parameters related to the
        /// 'openssl::x509::extension::KeyUsage' extension.
        /// The value for this field can either be (1) An
        /// empty vector which will forego this extension
        /// for the certificate or (2) A single value with
        /// the parameters for the 'openssl::x509::extension::KeyUsage'
        /// extension.
        /// Todo: this should be an optional but it is not yet supported
        /// by the 'cxx' crate.
        pub extension_key_usage: Vec<X509KeyUsage>,
        /// This controls the parameters passed to the
        /// 'openssl::x509::extension::BasicConstraints' extension.
        /// The value for this field should either be (1) an empty
        /// 'Vec' which will forego this extension or (2) a single
        /// value containing the parameters that will be passed
        /// to the 'openssl::x509::extension::BasicConstraints'
        /// extension.
        /// Todo: replace with an 'Option' once this is supported
        /// by the 'cxx' crate.
        pub extension_basic_constraints: Vec<X509BasicConstraints>
    }

    extern "Rust" {

        type CryptoNix;
        type OpensslPrivateKey;
        type OpensslX509Certificate;

        fn cryptonix_with_settings(settings: &CxxString) -> Box<CryptoNix>;
        fn rust_add(left: u64, right: u64) -> u64;

        fn cxx_openssl_private_key(self: &CryptoNix, key_identity: OpensslPrivateKeyIdentity) -> Result<Box<OpensslPrivateKey>>;

        fn cxx_openssl_x509_certificate(self: &CryptoNix, args: X509BuildParams) -> Result<Box<OpensslX509Certificate>>;

        fn public_pem(self: &OpensslPrivateKey) -> Result<String>;

        fn public_pem(self: &OpensslX509Certificate) -> Result<String>;
    }

    unsafe extern "C++" {
        include!("nix_crypto_plugin/include/nix_crypto.hh");

        fn init_primops();

        fn destroy_primops();
    }
}
