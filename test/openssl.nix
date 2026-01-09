{ pkgs, ... }:
let
  crypto = pkgs.callPackage ../crypto/default.nix {};
  inherit (crypto) openssl;

  # Generates an openssl key or returns said key if already
  # in the vault. However, the private-key itself is not
  # returned. We get an attribute set with operations
  # that can be performed with the private key.
  pk-rsa = openssl.private-key { 
    attrs = {
      vault = "openssl";
      name = "openssl-test-key";
    };
    type = "rsa";
  };
in
  {
    "It can generate a public/private key set" = { _assert, ... }:
      _assert.is-string pk-rsa.public-key-pem
    ;
    "It can generate a x509 self-signed certificate" = { _assert, ... }:
      let
        x509 = pk-rsa.x509 {
          subject-name = { CN = "subject"; };
          issuer-name = { CN = "issuer"; };
          serial = 1;
          start-date = "2026-01-09T21:29:36Z";
          expiry-date = "2036-01-09T21:29:36Z";
        };
      in
        # Derivation which outputs the public certificate of the CA
        # safe to write into the nix store.
        _assert.strings.has-prefix "-----BEGIN CERTIFICATE-----" x509.certificate-pem
    ;
  }

