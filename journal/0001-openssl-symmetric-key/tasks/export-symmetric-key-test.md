A test needs to be added to the test/openssl.nix file to validate that the `export-decryptable-key`
defined in the cyrpto/openssl/main.nix file works correctly. Follow the same structure of the existing
"It can export private key" but peform the following steps:
    1. Call the `export-decryptable-script` from nix code and export the `pk-rsa` key defined in the
    file as a pem string. The test should write that string to a temporary file.
    2. The test then uses the `nix-crypto-service` to dump the passphrase used to export the `pk-rsa` private key.
    See the file nix-crypto-service/src/main.rs to determine the right cli flags needed to perform
    this. Export this passphrase to a temporary file.
    3. Use the openssl binary program to decrypt the key exported in step 1 using the passphrase from
    step 2. Write the decrypted key to a temporary file.
    4. Use the openssl binary program to sign a value using the key from step 3. If openssl reports no
    errors you may assume that the test was successful.
