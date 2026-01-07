{ pkgs, ... }:
let
  nix-main = pkgs.nixVersions.nix_2_31;
  nix-components = pkgs.nixVersions.nixComponents_2_31;
  nix-crypto-plugin = pkgs.rustPlatform.buildRustPackage {
    pname = "nix-crypto-plugin";
    version = "0.1.0";
    src = ./.;
    cargoLock.lockFile = ./Cargo.lock;
    nativeBuildInputs = [ pkgs.pkg-config ];
    doCheck = false;
    buildInputs =
      with pkgs;
      with nix-components; [
        nix-store
        nix-expr
        nix-cmd
        nix-fetchers
        boost
        cargo
        openssl
        nix-main
      ]
    ;
  };
  nix-crypto = 
    pkgs.stdenv.mkDerivation {
    	pname = "nix-crypto";
    	version = "1.0";
    	nativeBuildInputs = [ pkgs.makeWrapper ];
      src = ./.;
      dontUnpack = true;
      dontBuild = true;
    	installPhase = ''
    		mkdir -p $out/bin
    
    		makeWrapper ${nix-main}/bin/nix $out/bin/nix \
          --add-flags "--option plugin-files ${nix-crypto-plugin}/lib/libnix_crypto.so"
    	'';
    }
  ;
in
  {
    packages = {
      inherit nix-crypto-plugin nix-crypto;
      default = nix-crypto;
    };
  }
