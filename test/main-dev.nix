# Special file to run tests in the nix development shell with the cargo package
{ system, nixpkgs }:
let
  #flake = builtins.getFlake pwd;
  #pkgs = import flake.inputs.nixpkgs { system = builtins.currentSystem; };
  pkgs = import nixpkgs { inherit system; };
in
  pkgs.callPackage ./main.nix { inherit pkgs; }
