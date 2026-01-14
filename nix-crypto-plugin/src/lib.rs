use ctor::{ctor,dtor};

mod cxx_api;
mod cxx_bridge;

#[ctor]
fn init() {
    ffi::init_primops();
}

#[dtor]
fn exit() {
    ffi::destroy_primops();
}
