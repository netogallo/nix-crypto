fn main() {
    cxx_build::bridge("src/lib.rs")
        .file("src/nix_crypto.cc")
        .std("c++23")
        .compile("cxx");

    println!("cargo:rerun-if-changed=src/nix_crypto.cc");
    println!("cargo:rerun-if-changed=include/nix_crypto.hh");
}
