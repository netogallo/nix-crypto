# Special file to run tests in the nix development shell with the cargo package
{ pwd }:
let
  #flake = builtins.getFlake pwd;
  #pkgs = import flake.inputs.nixpkgs { system = builtins.currentSystem; };
  pkgs = import <nixpkgs> {};
in
  pkgs.callPackage ./main.nix {}
