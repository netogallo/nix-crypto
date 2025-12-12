use core::option::{Option};

use crate::error::*;

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
