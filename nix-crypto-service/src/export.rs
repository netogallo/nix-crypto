//! Implements the `export secret` subcommand of `nix-crypto-service`.
//!
//! ## Overview
//!
//! This module resolves the CLI arguments for `export secret`, constructs a
//! [`CryptoNix`] instance from the sled store configuration, retrieves (or
//! generates) the requested private key, and writes it to a file in PEM format.
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

use crate::common::{Error, NixCryptoArgs};

/// The supported identity types for the `export secret` subcommand.
pub enum IdentityType {
    /// An OpenSSL private key identity, identified by key type and key id.
    ///
    /// - `pkey_type`: the key type (e.g. `"rsa"`).
    /// - `pkey_id`: the key identity string (e.g. `"name=my-key&vault=openssl"`).
    OpensslPkey { pkey_type: String, pkey_id: String },
}

/// The resolved arguments for the `export secret` subcommand.
pub struct ExportArgs {
    /// The identity of the secret to export.
    pub identity_type: IdentityType,
    /// The file path to write the exported PEM private key to.
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

/// Resolves the identity type from the `--identity-type`, `--openssl-pkey-type`
/// and `--openssl-pkey-id` flags. Currently only `openssl-pkey` is supported.
fn resolve_identity_type(
    flag_identity_type: Option<String>,
    flag_openssl_pkey_type: Option<String>,
    flag_openssl_pkey_id: Option<String>,
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
        Some(other) => Err(Error::argument_error(format!(
            "Unrecognised identity type '{}'. Supported types are: openssl-pkey",
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
    flag_output_file: Option<String>,
) -> Result<ExportArgs, Error> {
    let identity_type = resolve_identity_type(
        flag_identity_type,
        flag_openssl_pkey_type,
        flag_openssl_pkey_id,
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
/// retrieves (or generates) the private key identified by [`ExportArgs::identity_type`],
/// converts it to PEM format, and writes it to [`ExportArgs::output_file`].
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

            println!("Successfully exported key to '{}'", args.output_file);
            Ok(())
        }
    }
}
