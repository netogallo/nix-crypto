{ lib, ... }:
let
  /**
    Produces a deterministic key identity string from an attribute set.
    Keys are sorted alphabetically and joined as `key=value` pairs separated
    by `&`. For example, `{ vault = "openssl"; name = "my-key"; }` produces
    `"name=my-key&vault=openssl"`.

    This string is used by both the nix-crypto plugin (to store the key) and
    `nix-crypto-service` (to look it up). The sort order ensures the identity
    is stable regardless of the order in which `attrs` is defined in nix.
  */
  to-key-identity = attrs:
    let
      keys = lib.sort (a: b: a < b) (lib.attrNames attrs);
      mk-entry = k:
        let
          value = attrs.${k};
        in
          "${k}=${value}"
      ;
    in
      lib.concatStringsSep "&" (lib.map mk-entry keys)
  ;
in
  {
    inherit to-key-identity;
  }
