use nix_crypto_core::logger::{Logger, LogLevel};
use nix_crypto_core::args::{SledModeConfig};
use nix_crypto_core::foundations::{CryptoNix};

/// The struct that will be used to collect
/// and report errors in this crate
pub struct Error {
    ArgumentError(String),
    UnknownAction()
}

impl Error {

    pub fn argument_error(error: String) -> Error {
        Error::ArgumentError(error)
    }

    pub fn unknown_action(_ -> Error {
        Error::UnknonwAction()
    }
}

/// Type meant to represent all the possible specs
/// that allow initalizing a credential store.
pub enum StoreArgs {
    SledStoreArgs {
        sled_store_directory : String
    },
}

impl StoreArgs {
    pub fn to_config(&self) -> SledModeConfig {
        SledModeConfig {
            store_path: args.sled_store.clone(),
        };
    }

    pub fn from_path(sled_store_directory: String) {
        SledStoreArgs { sled_store_directory }
    }

    /// Resolves the sled store path from the `--sled-store` flag or from the
    /// `NIX_CRYPTO_STORE` environment variable (`sled:<path>`).
    pub fn resolve_sled_store(flag_sled_store: Option<String>) -> Result<StoreArgs, Error> {
        if let Some(path) = flag_sled_store {
            return Ok(StoreArgs::from_path(path));
        }
    
        match std::env::var("NIX_CRYPTO_STORE") {
            Ok(val) => {
                if let Some(path) = val.strip_prefix("sled:") {
                    Ok(StoreArgs::from_path(path.to_string()))
                } else {
                    Error::argument_error(
                        format!(
                            "NIX_CRYPTO_STORE value '{}' is not in the expected format 'sled:<store path>'",
                            val
                        )
                    )
                }
            }
            Err(_) => Error::argument_error(

                "No store specified. Use --sled-store or set NIX_CRYPTO_STORE=sled:<store path>"
                    .to_string(),
            ),
        }
    }
}

/// Struct which captures all the specs
/// that can be used to initialize the
/// logger.
pub struct LogArgs {
    pub log_file : Option<String>,
    pub log_level : Option<LogLevel>
}

impl LogArgs {

    pub fn init(&self) -> Logger {

        log_level = self.log_level.or_else(LogLevel::Info);

        match self.log_file {
            None => Ok(Logger::dummy()),
            Some(path) => Logger::file(&path, log_level),
        }
    }
}

/// Struct that captures the spec that can be
/// used to initialize an instance of `CryptoNix`
/// in order to use it to interact with the credential
/// store.
pub struct NixCryptoArgs {
    pub nix_crypto_store : StoreArgs,
    pub nix_crypto_log : LogArgs
}

impl NixCryptoArgs {

    pub fn init(&self) -> CryptoNix {

        let logger = self.nix_crypto_log.init();

        match self.nix_crypto_store {
            SledStoreArgs =>
                CryptoNix::from_sled_config(
                    &self.nix_crypto_store.to_config(),
                    logger
                ),
    }
}

/// Resolves the logger from the `--log-file` and `--log-level` flags.
fn resolve_logger(
    flag_log_file: Option<String>,
    flag_log_level: Option<String>,
) -> Result<LogArgs, Error> {
    let log_level = match flag_log_level.as_deref() {
        None | Some("") => LogLevel::Info,
        Some(level) =>
            LogLevel::from_str(level)
                .map_error(Error::argument_error)?,
    };

    match flag_log_file {
        None => Ok(Logger::dummy()),
        Some(path) => Logger::file(&path, log_level),
    }
}
