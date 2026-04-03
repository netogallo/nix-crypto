{ pkgs, lib, prelude, ... }:
let
  modules = lib.makeScope pkgs.newScope (self:
  let
    load-type = file: { type = self.callPackage file {}; inherit file; };
  in
    {
      inherit prelude;
      main = self.callPackage ./main.nix {};
      x509-params-type = load-type ./x509-params-type.nix;
      private-key-spec-type = load-type ./private-key-spec-type.nix;
      export-decryptable-pkey-params-type = load-type ./export-decryptable-pkey-params-type.nix;
    }
  );
in
  modules.main
