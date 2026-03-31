# nix-crypto-service

A CLI tool for managing cryptographic secrets stored by the nix-crypto plugin.

## Exporting a Symmetric Key Passphrase

The `export secret` subcommand can be used to retrieve the passphrase
(random secret) associated with a symmetric key from the credential store
and write it to a file.

The passphrase is the raw random secret that is used as input to the key
derivation function (e.g. PBKDF2). It is not the derived AES key itself.

### Prerequisites

The nix-crypto plugin must have already stored a symmetric key in the
credential store. This happens automatically when the Nix expression
`private-key.export-decryptable-pkey` is evaluated for the first time
with a given set of symmetric key parameters.

The credential store is a sled database on the filesystem. Its location
must be provided either via the `--sled-store` flag or the
`NIX_CRYPTO_STORE` environment variable.

### Usage

    nix-crypto-service export secret \
      --identity-type openssl-symmetric-key \
      --openssl-symmetric-key-id <key-id> \
      --openssl-symmetric-key-derivation <derivation> \
      --openssl-symmetric-key-iterations <iterations> \
      --output-file <output-path> \
      [--sled-store <store-path>]

### Options

    --identity-type openssl-symmetric-key
        Selects the symmetric key export mode. This flag is required.

    --openssl-symmetric-key-id <key-id>
        The unique identifier for the symmetric key. This must match the
        key-id used in the Nix expression that created the key. Required.

    --openssl-symmetric-key-derivation <derivation>
        The key derivation scheme. Currently only "pbkdf2" is supported.
        Optional. Defaults to "pbkdf2".

    --openssl-symmetric-key-iterations <iterations>
        The number of iterations used for the key derivation function.
        This must match the value used in the Nix expression that created
        the key. Optional. Defaults to 600000.

    --output-file <output-path>
        The file path to write the passphrase to. The passphrase is written
        as a plain UTF-8 string with no trailing newline. Required.

    --sled-store <store-path>
        Path to the sled credential store on the filesystem. Optional if
        the NIX_CRYPTO_STORE environment variable is set to sled:<path>.

### Store Resolution

The credential store path is resolved in the following order:

  1. The --sled-store flag, if provided.
  2. The NIX_CRYPTO_STORE environment variable, which must be set to
     sled:<path>. For example:

         export NIX_CRYPTO_STORE=sled:/var/lib/nix-crypto/store

If neither is provided, the command will exit with an error.

### Matching the Nix Expression

The key-id, key-derivation, and iterations values passed to
nix-crypto-service must match exactly the values used in the Nix
expression that originally created the key. For example, given the
following Nix expression:

    private-key.export-decryptable-pkey {
      key-id = "my-database-key";
      key-derivation = "pbkdf2";
      iterations = 600000;
    }

The corresponding nix-crypto-service invocation would be:

    nix-crypto-service export secret \
      --identity-type openssl-symmetric-key \
      --openssl-symmetric-key-id my-database-key \
      --openssl-symmetric-key-derivation pbkdf2 \
      --openssl-symmetric-key-iterations 600000 \
      --output-file /run/secrets/my-database-key.passphrase \
      --sled-store /var/lib/nix-crypto/store

### Idempotency

Exporting the same key multiple times will always produce the same
passphrase, because the random secret is generated once and stored in
the credential store on the first call. Subsequent calls retrieve the
stored value.

### Security Considerations

  - The passphrase written to the output file is sensitive. Ensure the
    output file has appropriate permissions before invoking this command.
    For example:

        install -m 600 /dev/null /run/secrets/my-database-key.passphrase
        nix-crypto-service export secret ... --output-file /run/secrets/my-database-key.passphrase

  - The passphrase is a base64-encoded 16-byte (128-bit) random value. It
    is not the AES key itself; it is the input to the key derivation
    function.

  - The credential store should be stored on a filesystem with appropriate
    access controls, as it contains the raw passphrases for all symmetric
    keys managed by nix-crypto.

### Logging

Logging is disabled by default. To enable it, provide a log file path:

    nix-crypto-service export secret \
      --identity-type openssl-symmetric-key \
      --openssl-symmetric-key-id my-database-key \
      --output-file /run/secrets/my-database-key.passphrase \
      --log-file /var/log/nix-crypto-service.log \
      --log-level info

Valid log levels are: debug, info, warn, error. The default is info.
