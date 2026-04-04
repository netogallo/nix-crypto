{ pkgs, lib, prelude, ... }:
let
  modules = lib.makeScope pkgs.newScope (self:
  let
    load-type = file: { type = self.callPackage file {}; inherit file; };
  in
    {
      inherit prelude;
      main = self.callPackage ./main.nix {};
      types-common = self.callPackage ./types/common.nix {};
      x509-params-type = load-type ./types/x509-params-type.nix;
      private-key-spec-type = load-type ./types/private-key-spec-type.nix;
      export-decryptable-pkey-params-type = load-type ./types/export-decryptable-pkey-params-type.nix;
    }
  );
in
  modules.main
