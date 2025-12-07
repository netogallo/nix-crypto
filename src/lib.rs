use ctor::{ctor,dtor};

mod foundations;
mod age;
mod openssl;
mod cxx_api;
mod cxx_bridge;

use crate::cxx_bridge::ffi;

#[ctor]
fn init() {
    ffi::init_primops();
}

#[dtor]
fn exit() {
    ffi::destroy_primops();
}

