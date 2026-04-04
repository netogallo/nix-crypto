{ pkgs, lib, types-common, ... }:
let
  inherit (lib) types;
  inherit (types-common) attrs-type;
  private-key-spec-type =
    types.submodule {
      options = {
        attrs = attrs-type;
        type = lib.mkOption {
          description = ''
            The cryptographic protocol to be used to generate
            the private key. Currently supported:
              * rsa
          '';
          type = types.oneOf (lib.map types.strMatching [ "rsa" ]);
        };
      };
    }
  ;
in
  private-key-spec-type
