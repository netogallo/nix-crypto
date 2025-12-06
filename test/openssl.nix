{ ... }:
let
  inherit (builtins) openssl;

  # Generates an openssl key or returns said key if already
  # in the vault. However, the private-key itself is not
  # returned. We get an attribute set with operations
  # that can be performed with the private key.
  pk-rsa = openssl.private-key { 
    vault = "openssl";
    name = "openssl-test-key";
    type = "rsa";
  };
in
  {
    "It can generate a public/private key set" =
      pkgs.writeText "result" "${pk-rsa.public-key-pem}"
    ;
    "It can generate a certificate authority" =
      let
        x509-ca = pk-rsa.x509-ca {
        };
      in
        # Derivation which outputs the public certificate of the CA
        # safe to write into the nix store.
        pkgs.writeText "result" "${x509-ca.certificate}"
    ;
  }

