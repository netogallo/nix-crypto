//! # nix-crypto-service
//!
//! A CLI tool for managing cryptographic secrets stored by the nix-crypto plugin.
//!
//! ## Usage
//!
//! ### Export a secret
//!
//! Exports a private key from the sled store to a PEM file:
//!
//! ```text
//! nix-crypto-service export secret \
//!   --sled-store <path> \
//!   --identity-type openssl-pkey \
//!   --openssl-pkey-type rsa \
//!   --openssl-pkey-id <identity> \
//!   --output-file <path>
//! ```
//!
//! If `--sled-store` is not provided, the store path is resolved from the
//! `NIX_CRYPTO_STORE` environment variable, which must be set to `sled:<path>`.
//!
//! ### Logging
//!
//! Logging is optional. If `--log-file` is provided, log entries are written
//! to the specified file in append mode. The minimum log level can be set with
//! `--log-level` (default: `info`).
//!
//! ## Argument parsing
//!
//! This binary uses [`docopt`] for argument parsing. Note that `docopt` in Rust
//! skips `argv[0]` (the binary name) when parsing arguments. As a result, the
//! usage patterns must include the literal `nix-crypto-service` token so that
//! patterns are matched correctly when invoked directly. When using
//! `cargo run nix-crypto-service --version`, cargo passes `nix-crypto-service`
//! as `argv[1]`, which is why that works while invoking the binary directly
//! with `--version` does not match the pattern.

use docopt::Docopt;
use serde::Deserialize;

mod export;

const USAGE: &str = "
Usage:
    nix-crypto-service --version
    nix-crypto-service export secret [--sled-store <sled_store>] --identity-type <identity_type> [--openssl-pkey-type <openssl_pkey_type>] [--openssl-pkey-id <openssl_pkey_id>] --output-file <output_file> [--log-file <log_file>] [--log-level <log_level>]
    nix-crypto-service --help

Options:
    -h, --help                                      Show this help message.
    -v, --version                                   Show the version.
    --sled-store <sled_store>                       Path to the sled store on the filesystem.
    --identity-type <identity_type>                 The identity type being exported.
    --openssl-pkey-type <openssl_pkey_type>         The openssl private key type (required when --identity-type is 'openssl-pkey').
    --openssl-pkey-id <openssl_pkey_id>             The openssl private key id (required when --identity-type is 'openssl-pkey').
    --output-file <output_file>                     The file to write the exported secret to.
    --log-file <log_file>                           Path to the log file. If absent, logging is disabled.
    --log-level <log_level>                         Minimum log level: debug, info, warn, error [default: info].
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_version: bool,
    cmd_export: bool,
    cmd_secret: bool,
    flag_sled_store: Option<String>,
    flag_identity_type: Option<String>,
    flag_openssl_pkey_type: Option<String>,
    flag_openssl_pkey_id: Option<String>,
    flag_output_file: Option<String>,
    flag_log_file: Option<String>,
    flag_log_level: Option<String>,
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.argv(std::env::args())))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!("nix-crypto-service {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    if args.cmd_export && args.cmd_secret {
        let export_args = export::resolve_args(
            args.flag_sled_store,
            args.flag_identity_type,
            args.flag_openssl_pkey_type,
            args.flag_openssl_pkey_id,
            args.flag_output_file,
            args.flag_log_file,
            args.flag_log_level,
        )
        .unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });

        export::run_secret(export_args).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });

        return;
    }

    eprintln!("{}", USAGE);
    std::process::exit(1);
}
