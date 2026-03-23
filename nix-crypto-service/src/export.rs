//! Implements the `export secret` subcommand of `nix-crypto-service`.
//!
//! ## Overview
//!
//! This module resolves the CLI arguments for `export secret`, constructs a
//! [`CryptoNix`] instance from the sled store configuration, retrieves (or
//! generates) the requested private key or symmetric key passphrase, and writes
//! it to a file.
//!
//! ## Store resolution
//!
//! The sled store path is resolved from either:
//! - The `--sled-store` CLI flag, or
//! - The `NIX_CRYPTO_STORE` environment variable, which must be set to
//!   `sled:<path>`.
//!
//! ## Key identity
//!
//! The key identity string passed via `--openssl-pkey-id` must match exactly
//! the identity string produced by the nix-crypto plugin when the key was
//! stored. The identity string is produced by `to-key-identity` in
//! `crypto/openssl/main.nix`, which sorts the `attrs` keys alphabetically and
//! joins them as `key=value` pairs separated by `&`. For example:
//! `{ vault = "openssl"; name = "my-key"; }` → `"name=my-key&vault=openssl"`.
//! The `identity` field on the nix private key object exposes this string
//! directly so callers do not need to reconstruct it manually.

use nix_crypto_core::openssl::ffi::IsOpensslPrivateKeyIdentity;
use nix_crypto_core::openssl::decryptable::IsOpensslSymmetricKeyIdentity;

use crate::common::{Error, NixCryptoArgs};

/// The supported identity types for the `export secret` subcommand.
pub enum IdentityType {
    /// An OpenSSL private key identity, identified by key type and key id.
    ///
    /// - `pkey_type`: the key type (e.g. `"rsa"`).
    /// - `pkey_id`: the key identity string (e.g. `"name=my-key&vault=openssl"`).
    OpensslPkey {
        pkey_type: String,
        pkey_id: String,
    },
    /// An OpenSSL symmetric key identity. The passphrase (random secret) for
    /// this key will be retrieved from the store and written to the output file.
    ///
    /// - `key_id`: a unique identifier for the symmetric key.
    /// - `key_derivation`: the key derivation scheme (e.g. `"pbkdf2"`).
    /// - `iterations`: the number of iterations for the key derivation function.
    OpensslSymmetricKey {
        key_id: String,
        key_derivation: String,
        iterations: u32,
    },
}

/// The resolved arguments for the `export secret` subcommand.
pub struct ExportArgs {
    /// The identity of the secret to export.
    pub identity_type: IdentityType,
    /// The file path to write the exported secret to.
    pub output_file: String,
    /// The arguments used to build the `CryptoNix` instance.
    pub nix_crypto_args: NixCryptoArgs,
}

struct OpensslPkeyIdentity {
    pkey_type: String,
    pkey_id: String,
}

impl IsOpensslPrivateKeyIdentity for OpensslPkeyIdentity {
    fn key_type(&self) -> &String {
        &self.pkey_type
    }

    fn key_id(&self) -> &String {
        &self.pkey_id
    }
}

struct OpensslSymmetricKeyIdentity {
    key_id: String,
    key_derivation: String,
    iterations: u32,
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

const DEFAULT_KEY_DERIVATION: &str = "pbkdf2";
const DEFAULT_ITERATIONS: u32 = 600_000;

/// Resolves the identity type from the `--identity-type`, `--openssl-pkey-type`,
/// `--openssl-pkey-id`, `--openssl-symmetric-key-id`,
/// `--openssl-symmetric-key-derivation` and `--openssl-symmetric-key-iterations`
/// flags. Supported identity types are `openssl-pkey` and `openssl-symmetric-key`.
fn resolve_identity_type(
    flag_identity_type: Option<String>,
    flag_openssl_pkey_type: Option<String>,
    flag_openssl_pkey_id: Option<String>,
    flag_openssl_symmetric_key_id: Option<String>,
    flag_openssl_symmetric_key_derivation: Option<String>,
    flag_openssl_symmetric_key_iterations: Option<String>,
) -> Result<IdentityType, Error> {
    match flag_identity_type.as_deref() {
        Some("openssl-pkey") => {
            let pkey_type = flag_openssl_pkey_type.ok_or_else(|| Error::argument_error(
                "--openssl-pkey-type is required when --identity-type is 'openssl-pkey'".to_string()
            ))?;
            let pkey_id = flag_openssl_pkey_id.ok_or_else(|| Error::argument_error(
                "--openssl-pkey-id is required when --identity-type is 'openssl-pkey'".to_string()
            ))?;
            Ok(IdentityType::OpensslPkey { pkey_type, pkey_id })
        }
        Some("openssl-symmetric-key") => {
            let key_id = flag_openssl_symmetric_key_id.ok_or_else(|| Error::argument_error(
                "--openssl-symmetric-key-id is required when --identity-type is 'openssl-symmetric-key'".to_string()
            ))?;
            let key_derivation = flag_openssl_symmetric_key_derivation
                .unwrap_or_else(|| DEFAULT_KEY_DERIVATION.to_string());
            let iterations = match flag_openssl_symmetric_key_iterations {
                None => DEFAULT_ITERATIONS,
                Some(s) => s.parse::<u32>().map_err(|_| Error::argument_error(
                    format!("--openssl-symmetric-key-iterations must be a positive integer, got '{}'", s)
                ))?,
            };
            Ok(IdentityType::OpensslSymmetricKey { key_id, key_derivation, iterations })
        }
        Some(other) => Err(Error::argument_error(format!(
            "Unrecognised identity type '{}'. Supported types are: openssl-pkey, openssl-symmetric-key",
            other
        ))),
        None => Err(Error::argument_error(
            "--identity-type is required for export secret".to_string()
        )),
    }
}

/// Resolves all CLI flags into an [`ExportArgs`] struct.
pub fn resolve_args(
    nix_crypto_args: NixCryptoArgs,
    flag_identity_type: Option<String>,
    flag_openssl_pkey_type: Option<String>,
    flag_openssl_pkey_id: Option<String>,
    flag_openssl_symmetric_key_id: Option<String>,
    flag_openssl_symmetric_key_derivation: Option<String>,
    flag_openssl_symmetric_key_iterations: Option<String>,
    flag_output_file: Option<String>,
) -> Result<ExportArgs, Error> {
    let identity_type = resolve_identity_type(
        flag_identity_type,
        flag_openssl_pkey_type,
        flag_openssl_pkey_id,
        flag_openssl_symmetric_key_id,
        flag_openssl_symmetric_key_derivation,
        flag_openssl_symmetric_key_iterations,
    )?;

    let output_file = flag_output_file.ok_or_else(|| Error::argument_error(
        "--output-file is required for export secret".to_string()
    ))?;

    Ok(ExportArgs {
        identity_type,
        output_file,
        nix_crypto_args,
    })
}

/// Runs the `export secret` subcommand.
///
/// Constructs a [`CryptoNix`] instance from the sled store configuration,
/// retrieves (or generates) the secret identified by [`ExportArgs::identity_type`],
/// and writes it to [`ExportArgs::output_file`].
///
/// - For `openssl-pkey`: retrieves the private key and writes it as PEM.
/// - For `openssl-symmetric-key`: retrieves the passphrase (random secret) and
///   writes it as a plain string.
pub fn run_secret(args: ExportArgs) -> Result<(), Error> {

    let crypto_nix = args.nix_crypto_args.init()?;

    match args.identity_type {
        IdentityType::OpensslPkey { pkey_type, pkey_id } => {
            let identity = OpensslPkeyIdentity { pkey_type, pkey_id };

            let key = crypto_nix
                .openssl_private_key(&identity)
                .map_err(|e| Error::argument_error(format!("Failed to obtain private key: {}", e)))?;

            let pem_bytes = key
                .key_to_pem()
                .map_err(|e| Error::argument_error(format!("Failed to convert key to PEM: {}", e)))?;

            let pem_string = String::from_utf8(pem_bytes)
                .map_err(|e| Error::argument_error(format!("Failed to convert PEM bytes to string: {}", e)))?;

            std::fs::write(&args.output_file, pem_string)
                .map_err(|e| Error::argument_error(format!("Failed to write key to '{}': {}", args.output_file, e)))?;

            println!("Successfully exported private key to '{}'", args.output_file);
            Ok(())
        }
        IdentityType::OpensslSymmetricKey { key_id, key_derivation, iterations } => {
            let identity = OpensslSymmetricKeyIdentity { key_id, key_derivation, iterations };

            let passphrase = crypto_nix
                .openssl_symmetric_key_passphrase(&identity)
                .map_err(|e| Error::argument_error(format!("Failed to obtain symmetric key passphrase: {}", e)))?;

            std::fs::write(&args.output_file, passphrase)
                .map_err(|e| Error::argument_error(format!("Failed to write passphrase to '{}': {}", args.output_file, e)))?;

            println!("Successfully exported symmetric key passphrase to '{}'", args.output_file);
            Ok(())
        }
    }
}
