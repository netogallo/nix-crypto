fn main() {
    pkg_config::Config::new()
		    .probe("nix-main")
		    .expect("The Nix development libraries are needed to build this project.");


    let modules = vec!("src/cxx_bridge.rs");
    cxx_build::bridges(modules)
        .file("src/nix_crypto.cc")
        .std("c++23")
        .compile("cxx");

    println!("cargo:rerun-if-changed=src/nix_crypto.cc");
    println!("cargo:rerun-if-changed=include/nix_crypto.hh");
}
