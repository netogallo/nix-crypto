use regex::Regex;
use std::collections::HashMap;

use crate::error::{Error};

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

const K_MODE : &str = "mode";
const K_STORE_PATH : &str = "store-path";
const K_FILESYSTEM_MODE : &str = "filesystem";

/// Configuration representing the mode which uses
/// the 'sled' crate to store credentials. This
/// mode requries a path as input which determines
/// where the values are to be stored. The mode
/// must be used with care as the credentials are
/// stored unencrypted at the specified location.
pub struct SledModeConfig {
    store_path : String
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

/// Represents the mode used to run 'CryptoNix'. Mode
/// refers to the mechanism which 'CryptoNix' will use
/// to managed the private credentials. If no mode
/// is specified via the Nix "--options", the 'ErrorMode'
/// is automatically selected which results in 'CryptoNix'
/// throwing errors when invoked via the Nix language.
pub enum CryptoNixMode {
    ErrorMode(Error),
    SledMode(SledModeConfig)
}

/// This struct represents the configuration that
/// will be used to run 'CryptoNix'. This is constructed
/// from the args supplied via the command line which get
/// parsed using the 'parse_args' function.
pub struct CryptoNixArgs {
    mode : CryptoNixMode
}

impl CryptoNixArgs {

    fn from_error(error: Error) -> CryptoNixArgs {
        CryptoNixArgs { mode: CryptoNixMode::ErrorMode(error) }
    }

    fn from_sled_mode(sled: SledModeConfig) -> CryptoNixArgs {
        CryptoNixArgs { mode: CryptoNixMode::SledMode(sled) }
    }

    fn from_args_with_error(query: &str) -> Result<CryptoNixArgs, Error> {

        let args = parse_args(query);
        let mode = &args.get(K_MODE).ok_or(Error::from_message(format!("The '{}' option is not present in the CryptoNix parameters.", K_MODE)))?;

        if mode.len() == 0 {
            return Error::fail_with(
                format!("No mode provided to cryptonix. Please specify a mode to use CryptoNix via the 'option extra-cryptonix-args {}={}'", K_MODE, K_FILESYSTEM_MODE)
            )
        } else if mode.len() > 1 {
            return Error::fail_with(
                "Multiple modes have been provided to CryptoNix. Only a single mode must be supplied.".to_string()
            )
        }

        match &mode[0][..] {
            K_FILESYSTEM_MODE => Ok(
               Self::from_sled_mode(SledModeConfig::from_parsed_args(&args)?)
            ),
            other => Error::fail_with(format!("The supplied mode '{}' is not a known CryptoNix operating mode. Plese consult the manual.", other))
        }
    }

    pub fn from_args(query: &str) -> CryptoNixArgs {

        match Self::from_args_with_error(query) {
            Ok(args) => args,
            Err(e) => Self::from_error(e)
        }
    }
}


