{ lib }:
let
  inherit (lib) types;
  attrs-type = lib.mkOption {
    description = ''
      Nix crypto does not expose private key to the nix
      language in order to avoid writing them to the store.
      However, all private keys are given a unique identifier
      (specified by the user) whic will always refer to the
      same private key. The key will be generated once and
      subseuqent calls will re-use the existing key. This
      is done to retain referential transparency on cryptographic
      private keys.

      In theory, nix crypto could instead return the private
      key as a string and that could be passed to other functions
      to perform cryptography. This would be referentially transparent
      as the string could be copied/saved/restored w/o any impact.
      The 'identifier' is used instead of directly using the key.
      As long as the same store is used with cryptonix, it will
      refer to the same key.

      The unique identifier is derived from an attribute set with
      string values. This is done for convenience and to make
      cryptography more readable.
    '';
    type = types.attrsOf types.str;
  };
in
  {
    inherit attrs-type;
  }
