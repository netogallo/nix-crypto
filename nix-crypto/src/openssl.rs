use openssl::pkey::{Public, Private};
use openssl::rsa::{Rsa};

use crate::foundations::{Error};

pub enum OpensslKeyType {
    RsaKeyType
}

pub enum OpensslKey {
    RsaPrivateKey(Rsa<Private>)
}

impl OpensslKey {

    pub fn new(key_type : OpensslKeyType) -> Result<OpensslKey, Error> {

        let rsa = Rsa::generate(4096)?;
        return Ok(OpensslKey::RsaPrivateKey(rsa));
    }
}

