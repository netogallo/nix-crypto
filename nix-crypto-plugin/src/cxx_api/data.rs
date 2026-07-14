use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use nix_crypto_core::envelope::{AesKeyDerivation, AesKeySize, AesMode,
    Envelope, OpensslPadding, RsaKeySize};
use nix_crypto_core::openssl::export::{AsymmetricEncryptionResult};

#[derive(Clone)]
pub struct NixUnionValue<'a> {
    union_cases: Vec<&'a str>,
    union_case: usize,
    union_value: Box<CxxNixValue<'a>>
}

impl<'a> NixUnionValue<'a> {

    pub fn case(&self) -> &'a str {
        self.union_cases[self.union_case]
    }
}

/// This type enumerates the rust types which can be expressed
/// as Nix values. It also captures various ownership semantics
/// that rust values may have in order to avoid cloning values
/// if it is possible to obtain and retain a reference to
/// the original value which is being represented.
#[derive(Clone)]
pub enum CxxNixValue<'a> {
    IntValue(i64),
    StringValueRef(&'a str),
    StringValueOwned(String),
    AttrsValue(&'a dyn IsNixAttrs),
    UnionValue(NixUnionValue<'a>)
}

impl<'a> CxxNixValue<'a> {

    pub fn create_union(
        union_cases: Vec<&'a str>,
        union_case: usize,
        value: CxxNixValue<'a>
    ) -> Self {

        if union_case >= union_cases.len() {
            panic!("The union's case must be in the range of options.")
        }

        CxxNixValue::UnionValue(
            NixUnionValue {
                union_value: Box::new(value),
                union_cases,
                union_case
            }
        )
    }

    pub fn as_base64_string(bin: &Vec<u8>) -> Self {
        CxxNixValue::StringValueOwned(
            STANDARD.encode(bin)
        )
    }
}

// A `CxxNixValue` can be constructed from a `str` reference.
// It will inherit the lifelne of the `str` reference. This
// is interpreted as a nix string.
impl<'a> From<&'a str> for CxxNixValue<'a> {

    fn from(value: &'a str) -> CxxNixValue<'a> {
        CxxNixValue::StringValueRef(value)
    }
}

impl<'a,'b> From<&'a u32> for CxxNixValue<'b> {

    fn from(value: &'a u32) -> CxxNixValue<'b> {
        CxxNixValue::IntValue(value.clone() as i64)
    }
}

impl<'a> From<String> for CxxNixValue<'a> {

    fn from(value: String) -> CxxNixValue<'a> {
        CxxNixValue::StringValueOwned(value)
    }
}

impl<'a> From<CxxNixValue<'a>> for Option<String> {

    fn from(value: CxxNixValue<'a>) -> Option<String> {
        match value {
            CxxNixValue::StringValueRef(v) => Option::Some(v.to_string()),
            CxxNixValue::StringValueOwned(v) => Option::Some(v),
            _ => Option::None
        }
    }
}

impl<'a> From<CxxNixValue<'a>> for Option<i64> {

    fn from(value: CxxNixValue<'a>) -> Option<i64> {
        match value {
            CxxNixValue::IntValue(i) => Option::Some(i),
            _ => Option::None
        }
    }
}

/// Values which can be naturally represented as a Nix attribute set
/// may implement this trait to formalize this. This avoids having
/// to write C++ glue code to convert the value into a Nix attribute set
/// as instances of this trait can be used to implement a generalized
/// conversion routine.
pub trait IsNixAttrs {

    fn keys(&self) -> Vec<&str>;

    fn get_value<'a>(&'a self, key: &str) -> Option<CxxNixValue<'a>>;
}

// Allow using instances of `NixUnionoValue` as
// an nix attribute set. Each of the cases in the union
// will become a nix attribute. The resulting nix attribute
// set will *only* contain the attribute corresponding to the
// union's case of the value.
impl IsNixAttrs for NixUnionValue<'_> {
    fn keys(&self) -> Vec<&str> {
        vec![ self.case() ]
    }

    fn get_value<'x>(&'x self, key: &str) -> Option<CxxNixValue<'x>> {

        if key == self.case() {
            Some(*self.union_value.clone())
        }
        else {
            None
        }
    }
}

// Allow converting values of type `AesMode` into
// nix values. A string representation of the mode is
// used for clarity, rather than representing the
// enum as a number.
impl From<&AesMode> for CxxNixValue<'static> {

    fn from(aes_mode: &AesMode) -> CxxNixValue<'static> {
        match aes_mode {
            AesMode::CBC => "cbc".into()
        }
    }
}

impl<'a,'b> From<&'a RsaKeySize> for CxxNixValue<'b> {

    fn from(key_size: &'a RsaKeySize) -> CxxNixValue<'b> {
        CxxNixValue::IntValue(key_size.into())
    }
}

impl<'a,'b> From<&'a AesKeySize> for CxxNixValue<'b> {

    fn from(key_size: &'a AesKeySize) -> CxxNixValue<'b> {
        CxxNixValue::IntValue(key_size.into())
    }
}

impl<'a> From<&'a OpensslPadding> for CxxNixValue<'static> {

    fn from(padding: &'a OpensslPadding) -> CxxNixValue<'static> {
        match padding {
            OpensslPadding::Pkcs1Oaep => "pkcs1_oaep".into()
        }
    }
}

// Fields for `AesKeyDerivation`
const K_AES_KEY_DERIVATION_AES_IV: &str = "aes-iv-base64";
const K_AES_KEY_DERIVATION_AES_PBKDF2_SALT: &str = "aes-pbkdf2-salt-base64";
const K_AES_KEY_DERIVATION_AES_PBKDF2_ROUNDS: &str = "aes-pbkdf2-rounds";

impl IsNixAttrs for AesKeyDerivation {

    fn keys(&self) -> Vec<&str> {

        match self {
            AesKeyDerivation::NoDerivation { .. } =>
                vec![K_AES_KEY_DERIVATION_AES_IV],
            AesKeyDerivation::Pbkdf2Derivation { .. } =>
                vec![ 
                    K_AES_KEY_DERIVATION_AES_IV,
                    K_AES_KEY_DERIVATION_AES_PBKDF2_SALT,
                    K_AES_KEY_DERIVATION_AES_PBKDF2_ROUNDS
                ]
        }
    }

    fn get_value<'a>(&'a self, key: &str) -> Option<CxxNixValue<'a>> {

        match self {
            AesKeyDerivation::NoDerivation {
                aes_iv
            } => match key {
                K_AES_KEY_DERIVATION_AES_IV => {
                    let vec = aes_iv.into();
                    Some(CxxNixValue::as_base64_string(&vec))
                },
                _ => None
            },
            AesKeyDerivation::Pbkdf2Derivation {
                aes_pbkdf2_salt,
                aes_pbkdf2_rounds
            } => match key {
                K_AES_KEY_DERIVATION_AES_PBKDF2_SALT => {
                    let vec = aes_pbkdf2_salt.into();
                    Some(CxxNixValue::as_base64_string(&vec))
                },
                K_AES_KEY_DERIVATION_AES_PBKDF2_ROUNDS =>
                    Some(aes_pbkdf2_rounds.into()),
                _ => None
            }
        }
    }
}

// Pattern cases for `AesKeyDerivation`
const K_AES_KEY_DERIVATION_NO_DERIVATION: &str = "no-derivation";
const K_AES_KEY_DERIVATION_PBKDF2_DERIVATION: &str = "pbkdf2-derivation";

impl<'a> From<&'a AesKeyDerivation> for CxxNixValue<'a> {

    fn from(drv: &'a AesKeyDerivation) -> CxxNixValue<'a> {

        let case =
            match drv {
                AesKeyDerivation::NoDerivation { .. } => 0,
                AesKeyDerivation::Pbkdf2Derivation { .. } => 1
            };
        CxxNixValue::create_union(
            vec![
                K_AES_KEY_DERIVATION_NO_DERIVATION,
                K_AES_KEY_DERIVATION_PBKDF2_DERIVATION
            ],
            case,
            CxxNixValue::AttrsValue(drv)
        )
    }
}

// Fields for OpensslRsaEnvelope case
const K_OPENSSL_RSA_KEY_SIZE: &str = "rsa-key-size";
const K_OPENSSL_RSA_PADDING: &str = "rsa-padding";
const K_OPENSSL_RSA_CIPHERTEXT: &str = "rsa-ciphertext-base64";

// Fields for OpensslAesEnvelope case
const K_OPENSSL_AES_KEY_SIZE: &str = "aes-key-size";
const K_OPENSSL_AES_KEY_DERIVATION: &str = "aes-key-derivation";
const K_OPENSSL_AES_MODE: &str = "aes-mode";
const K_OPENSSL_AES_CIPHERTEXT: &str = "aes-ciphertext-base64";

// Allow values of `Envelope` type to be converted into
// nix attribute sets. The `Envelope` type contains an
// encrypted payload with the encryption parameters. This
// allows nix code to know what decryption method is to
// be used to decrypt the envelope.
impl IsNixAttrs for Envelope {

    fn keys(&self) -> Vec<&str> {

        // The `Envelope` type is a rust union, therefore
        // the set of keys one of its values will have
        // depends on what case the union belongs to.
        match self {
            Self::OpensslRsaEnvelope { .. } => vec![
                K_OPENSSL_RSA_KEY_SIZE,
                K_OPENSSL_RSA_PADDING,
                K_OPENSSL_RSA_CIPHERTEXT
            ],
            Self::OpensslAesEnvelope { .. } => vec![
                K_OPENSSL_AES_KEY_SIZE,
                K_OPENSSL_AES_KEY_DERIVATION,
                K_OPENSSL_AES_MODE,
                K_OPENSSL_AES_CIPHERTEXT
            ]
        }
    }

    fn get_value<'a>(&'a self, key: &str) -> Option<CxxNixValue<'a>> {

        match self {
            Self::OpensslRsaEnvelope {
                rsa_key_size,
                rsa_padding,
                rsa_ciphertext
            } => match key {
                K_OPENSSL_RSA_KEY_SIZE =>
                    Some(rsa_key_size.into()),
                K_OPENSSL_RSA_PADDING =>
                    Some(rsa_padding.into()),
                K_OPENSSL_RSA_CIPHERTEXT =>
                    Some(CxxNixValue::as_base64_string(rsa_ciphertext)),
                _ => None
            },
            Self::OpensslAesEnvelope {
                aes_key_size,
                aes_key_derivation,
                aes_mode,
                aes_ciphertext
            } => match key {
                K_OPENSSL_AES_KEY_SIZE =>
                    Some(aes_key_size.into()),
                K_OPENSSL_AES_KEY_DERIVATION =>
                    Some(aes_key_derivation.into()),
                K_OPENSSL_AES_MODE =>
                    Some(aes_mode.into()),
                K_OPENSSL_AES_CIPHERTEXT =>
                    Some(CxxNixValue::as_base64_string(aes_ciphertext)),
                _ => None
            }
        }
    }
}

// The union cases for Envelope
const K_OPENSSL_RSA_ENVELOPE: &str = "openssl-rsa-envelope";
const K_OPENSSL_AES_ENVELOPE: &str = "openssl-aes-envelope";

impl<'a> From<&'a Envelope> for CxxNixValue<'a> {

    fn from(envelope: &'a Envelope) -> Self {

        let value = CxxNixValue::AttrsValue(envelope);
        let case =
            match envelope {
                Envelope::OpensslRsaEnvelope{..} => 0,
                Envelope::OpensslAesEnvelope{..} => 1
            };

        CxxNixValue::create_union(
            vec![ K_OPENSSL_RSA_ENVELOPE, K_OPENSSL_AES_ENVELOPE ],
            case,
            value
        )
    }
}

const K_ENCRYPTED_EPHEMERAL_KEY: &str = "encrypted-ephemeral-key";
const K_ENCRYPTED_PAYLOAD: &str = "encrypted-payload";

impl IsNixAttrs for AsymmetricEncryptionResult {

    fn keys(&self) -> Vec<&str> {
        vec![K_ENCRYPTED_EPHEMERAL_KEY, K_ENCRYPTED_PAYLOAD]
    }

    fn get_value<'a>(&'a self, key: &str) -> Option<CxxNixValue<'a>> {

        match key {
            K_ENCRYPTED_EPHEMERAL_KEY =>
                Some((&self.encrypted_ephermeral_key).into()),
            K_ENCRYPTED_PAYLOAD =>
                Some((&self.encrypted_payload).into()),
            _ => None
        }
    }
}

impl<'a> From<&'a AsymmetricEncryptionResult> for CxxNixValue<'a> {

    fn from(result: &'a AsymmetricEncryptionResult) -> CxxNixValue<'a> {

        CxxNixValue::AttrsValue(result)
    }
}

pub enum CxxNixAttrs<'a> {
    Owned(Box<dyn IsNixAttrs + 'a>),
    Ref(&'a dyn IsNixAttrs)
}

impl<'a> CxxNixAttrs<'a> {

    pub fn new_ref(inner: &'a dyn IsNixAttrs) -> Self {
        Self::Ref(inner)
    }

    pub fn new<T>(inner: T) -> Self
    where T : IsNixAttrs + 'a {
        Self::Owned(Box::new(inner))
    }

    fn attrs(&'a self) -> &'a dyn IsNixAttrs {

        match self {
            Self::Owned(inner) => inner.as_ref(),
            Self::Ref(inner) => *inner
        }
    }

    /// Returns a vector containing all the keys
    /// present in the attribute set.
    pub fn get_keys(&'a self) -> Vec<String> {
        self.attrs()
            .keys()
            .into_iter()
            .map(|k| k.to_string())
            .collect()
    }

    /// Try getting the value under a given key as an
    /// `i64`. If the key is missiong or the value
    /// is not an `i64`, an empty Vector is returned.
    /// Otherwise, a vector containing the value as
    /// a single element is returned.
    pub fn try_get_int(&'a self, key: &str) -> Vec<i64> {
        match
            self.attrs()
                .get_value(key)
                .and_then(|v| v.into())
        {
            Some(v) => {
                vec![v]
            }
            _ => Vec::new(),
        }
    }

    /// Attempt to get the value held under the given key as a
    /// `String`. If the key does not exist or the value is not
    /// a `String`, an empty `Vec` is returned. Otherwise, a
    /// `Vec` is returned containing the value as its sole element.
    pub fn try_get_str(&'a self, key: &str) -> Vec<String> {
        match
            self.attrs()
                .get_value(key)
                .and_then(|x| x.into())
        {
            Some(s) => vec![s],
            _ => Vec::new(),
        }
    }

    fn to_nix_attrs(value: CxxNixValue<'a>) -> Option<CxxNixAttrs<'a>> {

        match value {
            CxxNixValue::AttrsValue(v) => Some(Self::new_ref(v)),
            CxxNixValue::UnionValue(v) => Some(Self::Owned(Box::new(v))),
            _ => None
        }
    }

    /// Attempt getting the value under the given key as an attribute
    /// set. If the key is missing or the value is not an attribute set,
    /// an empty `Vec` is returned. Otherwise, a `Vec` containing a single
    /// `CxxNixAttrs` will be returned.
    /// Note that when calling this function in C++ code, the returned
    /// value's life is tied to the life of the object used to call the
    /// function. Even if this is not obvious from the types.
    pub fn try_get_attrs<'b>(&'a self, key: &'b str) -> Vec<CxxNixAttrs<'a>>
    where 'b : 'a {
        match
            self.attrs()
                .get_value(key)
                .and_then(Self::to_nix_attrs)
        {
            Some(v) => vec![ v ],
            _ => Vec::new(),
        }
    }
}
