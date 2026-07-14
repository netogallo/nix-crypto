use std::collections::HashMap;

use crate::error::{Error};

// ============================================================================
// Exportable trait
// ============================================================================

/// The exportable trait applies to all credentials that can be exported
/// as plaintext. This text is not expected to contain any encryption or
/// security.
pub trait Exportable {
    fn export(&self) -> Result<Vec<u8>, Error>;
}

/// This enum is meant to represent the rust types which can
/// be represented as primitive values in nix.
pub enum NixValue {
    NixIntValue(i32),
    NixStringValue(String),
    NixAttrsValue(NixAttrs)
}

/// This data structure is meant to represent data in such
/// a way that it can be represented as a Nix attribute set.
pub struct NixAttrs {
    nix_values : HashMap<String, NixValue>
}

impl<'a> NixAttrs {

    pub fn from_hash_map(nix_values: HashMap<String, NixValue>) -> NixAttrs {
        NixAttrs { nix_values }
    }

    pub fn keys(&'a self) -> Vec<&'a String> {
        self.nix_values.keys().collect()
    }

    pub fn get(&'a self, key: &String) -> Option<&'a NixValue> {
        self.nix_values.get(key)
    }

    pub fn iter(&'a self) -> std::collections::hash_map::Iter<'a, String, NixValue> {
        self.nix_values.iter()
    }
}

impl From<HashMap<String, NixValue>> for NixAttrs {
    fn from(value: HashMap<String, NixValue>) -> NixAttrs {
        NixAttrs::from_hash_map(value)
    }
}

impl From<String> for NixValue {
    fn from(value: String) -> NixValue {
        NixValue::NixStringValue(value)
    }
}
