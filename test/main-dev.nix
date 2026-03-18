# Special file to run tests in the nix development shell with the cargo package
{ system, nixpkgs, nix-crypto-service ? "$PWD/target/debug/nix-crypto-service" }:
let
  pkgs = import nixpkgs { inherit system; };
in
  pkgs.callPackage ./main.nix { inherit pkgs nix-crypto-service; }
