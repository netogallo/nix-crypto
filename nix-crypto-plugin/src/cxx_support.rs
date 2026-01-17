use core::option::{Option};

use nix_crypto_core::error::*;

/// This trait is meant to tag values that might be used as an
/// option in C++. This is here because the 'cxx' crate does
/// not natively support the 'Option' type. In the event that
/// the option has not been correctly encoded within the
/// value, an error should be raised.
pub trait CxxTryOption<T> {
    fn try_option(self: Self) -> Result<Option<T>, Error>;
}

impl<'a, T> CxxTryOption<&'a T> for &'a Vec<T> {

    fn try_option(self: &'a Vec<T>) -> Result<Option<&'a T>, Error> {

        if self.len() == 0 {
            return Ok(Option::None)
        } else if self.len() == 1 {
            return Ok(Some(&self[0]))
        } else {
            Err(Error::CxxError(
                format!(
                    "Expected vector to have at most one item, found {}",
                    self.len()
                )
            ))
        }
    }
}
