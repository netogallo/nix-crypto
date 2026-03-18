fn main() {
    let cpp_files = vec![
          "src/nix_crypto.cc"
        , "src/prelude.cc"
        , "src/openssl_primops.cc"
    ];

    let hh_files = vec![
          "include/nix_crypto.hh"
        , "include/prelude.hh"
        , "include/openssl_primops.hh"
    ];

    pkg_config::Config::new()
		    .probe("nix-main")
		    .expect("The Nix development libraries are needed to build this project.");

    let modules = vec!("src/cxx_bridge.rs");
    cxx_build::bridges(modules)
        .files(&cpp_files)
        .std("c++23")
        .compile("cxx");

    for file in cpp_files {
        println!("cargo:rerun-if-changed={}", file);
    }

    for file in hh_files {
        println!("cargo:rerun-if-changed={}", file);
    }
}
