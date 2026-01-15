use ctor::{ctor,dtor};
use cxx_bridge::ffi::{init_primops, destroy_primops};

mod cxx_api;
mod cxx_bridge;
mod cxx_support;

#[ctor]
fn init() {
    init_primops();
}

#[dtor]
fn exit() {
    destroy_primops();
}
