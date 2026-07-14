/**
  OpenSSL cryptographic operations for nix-crypto.
*/
{
  pkgs,
  prelude,
  common,
  private-key-spec-type,
  x509-params-type,
  export-decryptable-pkey-params-type,
  callPackage,
  ...
}@module:
let
  inherit (common) to-key-identity;
  inherit (pkgs) lib;
  inherit (lib) types;
  inherit (builtins.crypto) openssl;
  type-checker = prelude.type-checker { };

  /**
    Build an X.509 certificate signed by the given private key.
    Returns an attribute set with:
    - `certificate-pem`: the certificate in PEM format.
  */
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

  /**
    Export a private key credential encrypted with the given symmetric key.
    Returns a PEM-formatted string containing the AES-128-CBC encrypted
    private key.

    The same inputs (symmetric-key-params, key-ref, store) will always
    produce identical output, as the salt and IV are persisted in the store
    on the first call and reused thereafter.
  */
  export-decryptable-pkey = { key-ref, symmetric-key-params }:
  let
    key-id = to-key-identity symmetric-key-params.attrs;
    params = {
      inherit key-id;
      inherit (symmetric-key-params) key-derivation iterations;
    };
  in
    {
      inherit key-id;
      ciphertext-base64 = openssl.export-decryptable-pkey params key-ref;
    }
  ;

  /**
    Retrieve or generate an OpenSSL private key.
    Accepts a `key-spec` with:
    - `attrs`: an attribute set of key-value pairs used to construct the key
      identity string (e.g. `{ vault = "openssl"; name = "my-key"; }`).
    - `type`: the key type string (e.g. `"rsa"`).

    Returns an attribute set with:
    - `identity`: the key identity string produced by `to-key-identity`. Exposed
      so that callers (e.g. `nix-crypto-service`) can locate the key in the
      sled store without reconstructing the identity manually.
    - `public-key-pem`: the public key in PEM format, computed by the nix plugin.
    - `x509`: a function to build X.509 certificates signed by this key.
    - `export-decryptable-pkey`: a function to export this private key encrypted
      with a symmetric key.
    - `export-encrypted-pkey-pkey`: a function to export this private key encrypted
      with another private key.
  */
  private-key-impl = key-spec:
  let
    key-ref = {
      key-identity = to-key-identity key-spec.attrs;
      key-type = key-spec.type;
    };
  in
    {
      inherit key-spec;
      identity = key-ref.key-identity;
      public-key-pem = openssl.public-key-pem key-ref;
      x509 =
        type-checker.function
        [ { name = "x509-params"; type = x509-params-type; } ]
        (x509-params: x509 { inherit key-ref x509-params; })
      ;
      export-decryptable-pkey =
        type-checker.function
        [ { name = "symmetric-key-params"; type = export-decryptable-pkey-params-type; } ]
        (symmetric-key-params: export-decryptable-pkey { inherit key-ref symmetric-key-params; })
      ;
      export-encrypted-pkey-pkey =
        type-checker.function
        [ { name = "credential-spec"; type = private-key-spec-type; } ]
        (credential-spec:
          callPackage ./export-encrypted.nix {
            self-key-ref = key-ref;
            encryption-key-ref = {
              key-identity = to-key-identity credential-spec.attrs;
              key-type = credential-spec.type;
            };
          }
        )
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
