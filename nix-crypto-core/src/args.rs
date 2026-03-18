use regex::Regex;
use std::collections::HashMap;

use crate::error::Error;
use crate::logger::{Logger, LogLevel};

/// Parse the arguments provided to 'CryptoNix' as a
/// key/value data structure. The arguments are supplied
/// to crypto nix via the nix command line as follows:
/// --option extra-cryptonix-args "arg1=value&arg2=other_value".
fn parse_args(query: &str) -> HashMap<String, Vec<String>> {
    let re = Regex::new(r"(?:^|&)([^=&]+)=?([^&]*)").unwrap();

    let mut map: HashMap<String, Vec<String>> = HashMap::new();

    for caps in re.captures_iter(query) {
        let key = caps.get(1).unwrap().as_str().to_string();
        let value = caps.get(2).unwrap().as_str().to_string();

        map.entry(key)
            .or_insert_with(Vec::new)
            .push(value);
    }

    map
}

const K_MODE: &str = "mode";
const K_STORE_PATH: &str = "store-path";
const K_FILESYSTEM_MODE: &str = "filesystem";
const K_LOG_FILE: &str = "log-file";
const K_LOG_LEVEL: &str = "log-level";

const K_USAGE: &str = r#"
CryptoNix needs to be configured in order to be used. This
is achieved by using the "--option extra-cryptonix-args" flag
when running nix. The options supplied via this flag
are key/value sets formatted like "key1=value1&key2=value2".
Below is a concrete example:
    nix --option extra-cryptonix-args "mode=filesystem&store-path=/tmp/secrets"

Available options:
    mode=filesystem         Use the filesystem (sled) store.
    store-path=<path>       Path to the sled store (required for filesystem mode).
    log-file=<path>         Path to the log file. If absent, logging is disabled.
    log-level=<level>       Minimum log level: debug, info, warn, error. Defaults to info.
"#;

/// Configuration representing the mode which uses
/// the 'sled' crate to store credentials. This
/// mode requires a path as input which determines
/// where the values are to be stored. The mode
/// must be used with care as the credentials are
/// stored unencrypted at the specified location.
pub struct SledModeConfig {
    pub store_path: String,
}

impl SledModeConfig {
    pub fn from_parsed_args(args: &HashMap<String, Vec<String>>) -> Result<Self, Error> {
        let store_path =
            &args.get(K_STORE_PATH)
            .ok_or(
                Error::from_message(
                    format!("The CryptoNix '{}' mode requires the '{}' option, which must point to the location in the filesystem where CryptoNix will store the private credentials.", K_FILESYSTEM_MODE, K_STORE_PATH)
                )
            )?;

        if store_path.len() == 0 {
            return Error::fail_with(
                format!("The option '{}' must not be empty.", K_STORE_PATH)
            )
        } else if store_path.len() > 1 {
            return Error::fail_with(
                format!("The option '{}' must only be used once.", K_STORE_PATH)
            )
        }

        Ok(SledModeConfig { store_path: store_path[0].clone() })
    }
}

/// Configuration for the logger, parsed from the args string.
///
/// - `log_file`: path to the log file. If `None`, a [`DummySink`] is used.
/// - `log_level`: minimum log level. Defaults to [`LogLevel::Info`].
pub struct LoggerConfig {
    pub log_file: Option<String>,
    pub log_level: LogLevel,
}

impl LoggerConfig {
    /// Parse logger configuration from the args map.
    ///
    /// `log-file` is optional. `log-level` defaults to `info` if absent.
    pub fn from_parsed_args(args: &HashMap<String, Vec<String>>) -> Result<Self, Error> {
        let log_file = match args.get(K_LOG_FILE) {
            None => None,
            Some(values) if values.is_empty() => None,
            Some(values) if values.len() == 1 => Some(values[0].clone()),
            Some(_) => return Error::fail_with(
                format!("The option '{}' must only be used once.", K_LOG_FILE)
            ),
        };

        let log_level = match args.get(K_LOG_LEVEL) {
            None => LogLevel::Info,
            Some(values) if values.is_empty() => LogLevel::Info,
            Some(values) if values.len() == 1 => {
                LogLevel::from_str(&values[0])
                    .map_err(|e| Error::from_message(e))?
            },
            Some(_) => return Error::fail_with(
                format!("The option '{}' must only be used once.", K_LOG_LEVEL)
            ),
        };

        Ok(LoggerConfig { log_file, log_level })
    }

    /// Construct a [`Logger`] from this configuration.
    ///
    /// If `log_file` is `None`, a dummy logger is returned.
    /// If the log file cannot be opened, an error is returned.
    pub fn to_logger(self) -> Result<Logger, Error> {
        match self.log_file {
            None => Ok(Logger::dummy()),
            Some(path) => Logger::file(&path, self.log_level)
                .map_err(|e| Error::from_message(e)),
        }
    }
}

/// Represents the mode used to run 'CryptoNix'. Mode
/// refers to the mechanism which 'CryptoNix' will use
/// to manage the private credentials. If no mode
/// is specified via the Nix "--options", the 'ErrorMode'
/// is automatically selected which results in 'CryptoNix'
/// throwing errors when invoked via the Nix language.
pub enum CryptoNixMode {
    ErrorMode(Error),
    SledMode(SledModeConfig),
}

/// This struct represents the configuration that
/// will be used to run 'CryptoNix'. This is constructed
/// from the args supplied via the command line which get
/// parsed using the 'parse_args' function.
pub struct CryptoNixArgs {
    pub mode: CryptoNixMode,
    pub logger: Logger,
}

impl CryptoNixArgs {

    fn from_error(error: Error) -> CryptoNixArgs {
        CryptoNixArgs {
            mode: CryptoNixMode::ErrorMode(error),
            logger: Logger::dummy(),
        }
    }

    fn from_sled_mode(sled: SledModeConfig, logger: Logger) -> CryptoNixArgs {
        CryptoNixArgs {
            mode: CryptoNixMode::SledMode(sled),
            logger,
        }
    }

    fn from_args_with_error(query: &str) -> Result<CryptoNixArgs, Error> {

        let args = parse_args(query);
        let mode = &args.get(K_MODE).ok_or(Error::from_message(format!(
            "The '{}' option is not present in the CryptoNix parameters: '{}'.\n{}",
            K_MODE, query, K_USAGE
        )))?;

        if mode.len() == 0 {
            return Error::fail_with(
                format!("No mode provided to cryptonix. Please specify a mode to use CryptoNix via the 'option extra-cryptonix-args {}={}'", K_MODE, K_FILESYSTEM_MODE)
            )
        } else if mode.len() > 1 {
            return Error::fail_with(
                "Multiple modes have been provided to CryptoNix. Only a single mode must be supplied.".to_string()
            )
        }

        let logger_config = LoggerConfig::from_parsed_args(&args)?;
        let logger = logger_config.to_logger()?;

        match &mode[0][..] {
            K_FILESYSTEM_MODE => Ok(
                Self::from_sled_mode(SledModeConfig::from_parsed_args(&args)?, logger)
            ),
            other => Error::fail_with(format!(
                "The supplied mode '{}' is not a known CryptoNix operating mode. Please consult the manual.",
                other
            )),
        }
    }

    pub fn from_args(query: &str) -> CryptoNixArgs {
        match Self::from_args_with_error(query) {
            Ok(args) => args,
            Err(e) => Self::from_error(e),
        }
    }
}
