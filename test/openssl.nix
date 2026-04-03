/**
  Test suite for OpenSSL functionality.

  Accepts the following arguments:
  - `pkgs`: the nixpkgs package set.
  - `nix-crypto-service`: path to the `nix-crypto-service` binary.
*/
{ pkgs, nix-crypto-service, ... }:
let
  crypto = pkgs.callPackage ../crypto/default.nix {};
  inherit (crypto) openssl;

  # Generates an RSA key or returns the existing one from the store.
  # The private key itself is not returned — only operations that can
  # be performed with it.
  pk-rsa = openssl.private-key { 
    attrs = {
      vault = "openssl";
      name = "openssl-test-key";
    };
    type = "rsa";
  };

  # Symmetric key parameters used to encrypt the private key.
  # The same parameters must be passed to nix-crypto-service when
  # retrieving the passphrase.
  symmetric-key-params = {
    key-id = "openssl-test-symmetric-key";
    key-derivation = "pbkdf2";
    iterations = 600000;
  };

  # The encrypted PEM string produced by the nix-crypto plugin.
  # This is evaluated at nix evaluation time and interpolated into
  # the bash script below.
  encrypted-pem = pk-rsa.export-decryptable-pkey symmetric-key-params;
in
  {
    # Asserts that the plugin can generate or retrieve a public key in PEM format.
    "It can generate a public/private key set" = { _assert, ... }:
      _assert.is-string pk-rsa.public-key-pem
    ;

    # Asserts that the plugin can build a self-signed X.509 certificate
    # signed by the RSA key.
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

    /**
      Asserts that a private key stored by the nix-crypto plugin can be exported
      using `nix-crypto-service export secret`, and that the public key derived
      from the exported private key matches the public key computed by the plugin.

      The `NIX_CRYPTO_STORE` environment variable must point to the same sled store used
      by the nix-crypto plugin so that `nix-crypto-service` can locate the key.
    */
    "It can export the private key" = { _assert, ... }:
    let
      # The public key pem as computed by the nix plugin
      expected-public-key-pem = pk-rsa.public-key-pem;
      # The identity of the key, used to locate it in the store
      key-identity = pk-rsa.identity;
    in
      _assert.bash-script
      ''
        PRIVATE_KEY_FILE=$(mktemp)
        EXPECTED_PUBLIC_KEY_FILE=$(mktemp)
        RANDOM_FILE=$(mktemp)
        SIGNATURE_FILE=$(mktemp)

        # Write the expected public key pem to a temp file
        cat > "$EXPECTED_PUBLIC_KEY_FILE" << 'EOF'
        ${expected-public-key-pem}
        EOF

        # Export the private key using nix-crypto-service
        "${nix-crypto-service}" export secret \
          --sled-store "$NIX_CRYPTO_STORE" \
          --identity-type openssl-pkey \
          --openssl-pkey-type rsa \
          --openssl-pkey-id "${key-identity}" \
          --output-file "$PRIVATE_KEY_FILE" \
          --log-file "$NIX_CRYPTO_LOG" \
          --log-level debug

        # Generate a random value to sign
        dd if=/dev/urandom of="$RANDOM_FILE" bs=32 count=1 2>/dev/null

        # Sign the random value using the exported private key
        openssl dgst -sha256 -sign "$PRIVATE_KEY_FILE" -out "$SIGNATURE_FILE" "$RANDOM_FILE"

        # Verify the signature using the expected public key
        if ! openssl dgst -sha256 -verify "$EXPECTED_PUBLIC_KEY_FILE" -signature "$SIGNATURE_FILE" "$RANDOM_FILE"; then
          exit 1
        fi
        exit 0
      ''
    ;

    /**
      Asserts that a private key stored by the nix-crypto plugin can be exported
      in encrypted form using `export-decryptable-pkey`, that the passphrase used
      to encrypt it can be retrieved using `nix-crypto-service export secret` with
      `--identity-type openssl-symmetric-key`, and that the decrypted key can be
      used to sign data.

      The encryption is AES-128-CBC with PBKDF2-HMAC-SHA256 key derivation,
      compatible with `openssl enc -aes-128-cbc -pbkdf2`.

      The `NIX_CRYPTO_STORE` environment variable must point to the same sled store
      used by the nix-crypto plugin so that `nix-crypto-service` can locate the
      symmetric key.
    */
    "It can export decryptable key" = { _assert, ... }:
      _assert.bash-script
      ''
        ENCRYPTED_PEM_FILE=$(mktemp)
        PASSPHRASE_FILE=$(mktemp)
        DECRYPTED_KEY_FILE=$(mktemp)
        RANDOM_FILE=$(mktemp)
        SIGNATURE_FILE=$(mktemp)

        # Write the encrypted PEM (produced at nix evaluation time) to a temp file
        cat > "$ENCRYPTED_PEM_FILE" << 'EOF'
        ${encrypted-pem}
        EOF

        # Retrieve the passphrase used to encrypt the private key
        "${nix-crypto-service}" export secret \
          --sled-store "$NIX_CRYPTO_STORE" \
          --identity-type openssl-symmetric-key \
          --openssl-symmetric-key-id "${symmetric-key-params.key-id}" \
          --openssl-symmetric-key-derivation "${symmetric-key-params.key-derivation}" \
          --openssl-symmetric-key-iterations "${toString symmetric-key-params.iterations}" \
          --output-file "$PASSPHRASE_FILE" \
          --log-file "$NIX_CRYPTO_LOG" \
          --log-level debug

        # Decrypt the encrypted PEM using the passphrase.
        # The key and IV are derived from the passphrase and salt using
        # PBKDF2-HMAC-SHA256, matching the derivation done in decryptable.rs.
        openssl enc -d -aes-128-cbc -pbkdf2 \
          -iter ${toString symmetric-key-params.iterations} \
          -pass file:"$PASSPHRASE_FILE" \
          -in "$ENCRYPTED_PEM_FILE" \
          -out "$DECRYPTED_KEY_FILE"

        # Generate a random value to sign
        dd if=/dev/urandom of="$RANDOM_FILE" bs=32 count=1 2>/dev/null

        # Sign the random value using the decrypted private key
        if ! openssl dgst -sha256 -sign "$DECRYPTED_KEY_FILE" -out "$SIGNATURE_FILE" "$RANDOM_FILE"; then
          exit 1
        fi
        exit 0
      ''
    ;
  }
