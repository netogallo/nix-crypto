# This is a high level library built around the nix-crypto primitives. It is
# recommended that this library is used instead of directly relying on the
# primitives found in 'builtins.crypto'
{ pkgs, ... }:
let
  inherit (pkgs) lib;
  crypto = lib.makeScope pkgs.newScope (self:
    let
      x = 42;
    in
      {
        prelude = self.callPackage ./prelude.nix {};
        openssl = self.callPackage ./openssl.nix {};
      }
  );
in
  if lib.hasAttr "crypto" builtins
  then crypto
  else throw ''
    This library must be used with the nix-crypto plugin.
  ''

