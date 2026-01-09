{ pkgs, lib, prelude, ... }:
let
  modules = lib.makeScope pkgs.newScope (self: {
    inherit prelude;
    main = self.callPackage ./main.nix {};
    x509-params-type = self.callPackage ./x509-params-type.nix {};
    private-key-spec-type = self.callPackage ./private-key-spec-type.nix {};
  });
in
  modules.main
