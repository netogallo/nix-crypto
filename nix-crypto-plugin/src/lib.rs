use ctor::{ctor,dtor};
use cxx_bridge::ffi::{init_primops, destroy_primops};

mod cxx_api;
mod cxx_bridge;

#[ctor]
fn init() {
    init_primops();
}

#[dtor]
fn exit() {
    destroy_primops();
}
