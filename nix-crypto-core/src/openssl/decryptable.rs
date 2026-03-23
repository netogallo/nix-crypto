// The objective of this module is to define a method for the `CryptoNix`
// struct that allows safely exporting private credentials in the store
// by encrypting the values with a symmetric key that will reside in the store.
// Several steps are needed to achieve this.
// First, a `Decryptable` trait should be defined. This trait should have
// one method called `export` which determines how a credential is to
// be represented as a byte vector when getting exported as a decryptable. This
// is not the encrypted representation, rather the representation that will get
// encrypted later. One instance of this trait is to be defined for the
// `crate::openssl::pkey::Key` which should export a utf-8 representation
// of the pkcs8 pem of the key. The `crate::openssl::pkey::Key` struct already
// has a function to do this called `key_to_pem`, which is what should be used.
// The next step is to define a trait to identify openssl symmetric keys.
// Simiar to the existing `crate::openssl::pkey::IsOpensslPrivateKey` a new
// trait called `IsOpensslSymmetricKeyIdentity` needs to be defined. This trait
// will have two attributes:
//  1. `key_id` which will be a string that serves as the identity of the symmetric
//      key.
//  2. `key_derivation` which will indicate how the private key is to be derived
//      as the private keys should be representable as a `String`. At present,
//      the only supported derivation scheme will be "pbkdf2". Note that this
//      field should be a string, not an enum as, ulitmately, it will be supplied
//      from a nix expression.
// With the above items, it is then possible to define the `export_decryptable`
// method for `CryptoNix`. This method should accept two argumetns:
//  1. `key` which will be any value implementing the `IsOpensslSymmetricKeyIdentity`
//      trait.
//  2. `credential` which is any value implementing the `IsCryptoStoreKey` such that
//      the `Value` type argument implements the `Decryptable` trait.
// The
