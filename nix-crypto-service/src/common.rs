use nix_crypto_core::logger::{Logger, LogLevel};
use nix_crypto_core::args::SledModeConfig;
use nix_crypto_core::foundations::CryptoNix;

/// The enum that will be used to collect
/// and report errors in this crate.
pub enum Error {
    ArgumentError(String),
    UnknownAction,
}

impl Error {

    pub fn argument_error(error: String) -> Error {
        Error::ArgumentError(error)
    }

    pub fn unknown_action() -> Error {
        Error::UnknownAction
    }

    pub fn as_string(&self) -> String {
        match self {
            Error::ArgumentError(msg) => format!("Argument error: {}", msg),
            Error::UnknownAction => "Unknown action.".to_string(),
        }
    }
}

/// Type meant to represent all the possible specs
/// that allow initializing a credential store.
pub enum StoreArgs {
    SledStoreArgs {
        sled_store_directory: String,
    },
}

impl StoreArgs {

    pub fn to_config(&self) -> SledModeConfig {
        match self {
            StoreArgs::SledStoreArgs { sled_store_directory } => SledModeConfig {
                store_path: sled_store_directory.clone(),
            },
        }
    }

    pub fn from_path(sled_store_directory: String) -> StoreArgs {
        StoreArgs::SledStoreArgs { sled_store_directory }
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
                    Err(Error::argument_error(format!(
                        "NIX_CRYPTO_STORE value '{}' is not in the expected format 'sled:<store path>'",
                        val
                    )))
                }
            }
            Err(_) => Err(Error::argument_error(
                "No store specified. Use --sled-store or set NIX_CRYPTO_STORE=sled:<store path>"
                    .to_string(),
            )),
        }
    }
}

/// Struct which captures all the specs
/// that can be used to initialize the logger.
pub struct LogArgs {
    pub log_file: Option<String>,
    pub log_level: Option<LogLevel>,
}

impl LogArgs {

    pub fn init(&self) -> Result<Logger, Error> {
        let log_level = self.log_level.unwrap_or(LogLevel::Info);

        match &self.log_file {
            None => Ok(Logger::dummy()),
            Some(path) => Logger::file(path, log_level)
                .map_err(|e| Error::argument_error(e)),
        }
    }

    pub fn from_flags(
        flag_log_file: Option<String>,
        flag_log_level: Option<String>,
    ) -> Result<LogArgs, Error> {
        let log_level = match flag_log_level.as_deref() {
            None | Some("") => None,
            Some(level) => Some(
                LogLevel::from_str(level)
                    .map_err(|e| Error::argument_error(e))?,
            ),
        };

        Ok(LogArgs {
            log_file: flag_log_file,
            log_level,
        })
    }
}

/// Struct that captures the spec that can be
/// used to initialize an instance of `CryptoNix`
/// in order to use it to interact with the credential
/// store.
pub struct NixCryptoArgs {
    pub nix_crypto_store: StoreArgs,
    pub nix_crypto_log: LogArgs,
}

impl NixCryptoArgs {

    pub fn init(&self) -> Result<CryptoNix, Error> {
        let logger = self.nix_crypto_log.init()?;
        let config = self.nix_crypto_store.to_config();
        Ok(CryptoNix::from_sled_config(&config, logger))
    }

    pub fn from_flags(
        flag_sled_store: Option<String>,
        flag_log_file: Option<String>,
        flag_log_level: Option<String>,
    ) -> Result<NixCryptoArgs, Error> {
        let nix_crypto_store = StoreArgs::resolve_sled_store(flag_sled_store)?;
        let nix_crypto_log = LogArgs::from_flags(flag_log_file, flag_log_level)?;
        Ok(NixCryptoArgs { nix_crypto_store, nix_crypto_log })
    }
}
