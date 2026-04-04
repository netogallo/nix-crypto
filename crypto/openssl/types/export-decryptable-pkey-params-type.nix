{ lib, types-common, }:
let
  inherit (lib) types;
in
  types.submodule {
    options = {
      attrs = types-common.attrs-type;

      key-derivation = lib.mkOption {
        type = types.enum [ "pbkdf2" ];
        default = "pbkdf2";
        description = ''
          The key derivation scheme to use when deriving the AES key
          from the random secret. Currently only `pbkdf2` is supported.
        '';
      };

      iterations = lib.mkOption {
        type = types.int;
        description = ''
          The number of iterations to use for the key derivation function.
          Higher values increase security but also increase computation time.
        '';
      };
    };
  }
