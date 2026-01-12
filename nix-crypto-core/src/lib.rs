use ctor::{ctor,dtor};

mod error;
mod args;
mod foundations;
mod age;
mod openssl;
mod cxx_api;
mod cxx_bridge;
mod cxx_support;
mod store;

use crate::cxx_bridge::ffi;

