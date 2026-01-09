{ pkgs, prelude, private-key-spec-type, x509-params-type, ... }@module:
let
  inherit (pkgs) lib;
  inherit (lib) types;
  inherit (builtins.crypto) openssl;
  type-checker = prelude.type-checker {
    file = "${./openssl.nix}";
  };
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
  x509 = { key-ref, x509-params }:
  let
    x509-params-all =
      x509-params
      // { signing-private-key-identity = key-ref; }
    ;
  in
    {
      certificate-pem = openssl.x509-pem x509-params-all;
    }
  ;
  private-key-impl = key-spec:
  let
    key-ref = {
      key-identity = to-key-identity key-spec.attrs;
      key-type = key-spec.type;
    };
  in
    {
      public-key-pem = openssl.public-key-pem key-ref;
      x509 =
        type-checker.function
        [ { name = "x509-params"; type = x509-params-type; } ]
        (x509-params: x509 { inherit key-ref x509-params; })
      ;
    }
  ;

  private-key =
    type-checker.function
    [ { name = "key-spec"; type = private-key-spec-type; } ]
    private-key-impl
  ;
in
  { inherit private-key; }
