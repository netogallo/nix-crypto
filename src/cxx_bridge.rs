// This module will get parsed by the cxx:builder. Avoid anything
// other than definitions strictly needed for the C++ bridge, as
// any changes here incurr long re-compilation. For utilities
// related to the CXX bridge, use the cxx_support module. Function
// implementations for the functions in this module should be placed
// in cxx_api
use cxx::{CxxString, UniquePtr};

use crate::error::{Error};
use crate::cxx_api::*;
use crate::openssl;
use crate::foundations::{CryptoNix};

#[cxx::bridge]
pub mod ffi {

    struct OpensslPrivateKeyIdentity {
        key_type: String,
        key_id : String
    }

    struct X509NameItem {
        entry_name: String,
        entry_value: String
    }

    struct X509KeyUsage {
        critical: bool,
        key_cert_sign: bool,
        crl_sign: bool
    }

    struct X509BasicConstraints {
        critical: bool,
        ca: bool
    }

    /// This struct identifies a X509Certificate. Note that
    /// each parameter has additional constraints. The expectation
    /// is that the same set of parameters will result in the same
    /// certificate accross multiple invocations.
    struct X509BuildParams {
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
        subject_public_key: Vec<String>,
        /// The private key that will be used to sign the certificate.
        signing_private_key_identity: OpensslPrivateKeyIdentity,
        /// The name components of the certificate. Note that for
        /// identity purposes, the order in which they are defined
        /// does not matter. Furthermore, duplicate keys are not
        /// allowed.
        ca_name: Vec<X509NameItem>,
        /// The serial of the certificate
        serial: u64,
        /// The starting day of the certificate's validity. Note
        /// that this will be parsed into a proper 'Date', therefore the
        /// format does not matter for identity purposes.
        start_date: String,
        /// The expirly date of the certificate. Note that this
        /// will be parsed into a propoer 'Date', therefore the format
        /// does not matter for identity purposes.
        expiry_date: String,
        /// This controls the parameters related to the
        /// 'openssl::x509::extension::KeyUsage' extension.
        /// The value for this field can either be (1) An
        /// empty vector which will forego this extension
        /// for the certificate or (2) A single value with
        /// the parameters for the 'openssl::x509::extension::KeyUsage'
        /// extension.
        /// Todo: this should be an optional but it is not yet supported
        /// by the 'cxx' crate.
        extension_key_usage: Vec<X509KeyUsage>,
        /// This controls the parameters passed to the
        /// 'openssl::x509::extension::BasicConstraints' extension.
        /// The value for this field should either be (1) an empty
        /// 'Vec' which will forego this extension or (2) a single
        /// value containing the parameters that will be passed
        /// to the 'openssl::x509::extension::BasicConstraints'
        /// extension.
        /// Todo: replace with an 'Option' once this is supported
        /// by the 'cxx' crate.
        extension_basic_constraints: Vec<X509BasicConstraints>
    }

    extern "Rust" {

        type CryptoNix;

        fn cryptonix_with_settings(settings: &CxxString) -> Box<CryptoNix>;
        fn rust_add(left: u64, right: u64) -> u64;

        type OpensslPrivateKey;
        fn cxx_openssl_private_key(self: &CryptoNix, key_identity: OpensslPrivateKeyIdentity) -> Result<Box<OpensslPrivateKey>>;

        fn public_pem(self: &OpensslPrivateKey) -> Result<String>;

    }

    unsafe extern "C++" {
        include!("nix-crypto/include/nix_crypto.hh");

        fn init_primops();

        fn destroy_primops();
    }
}
