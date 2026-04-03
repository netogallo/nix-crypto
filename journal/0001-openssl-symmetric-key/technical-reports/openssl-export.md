# OpenSSL Private Key Export Test — Knowledge Dump

## Overview

This document captures all knowledge gathered during the implementation of the
"It can export the private key" test in `test/openssl.nix`.

---

## What the test does

The test verifies that:
1. A private key stored in the sled store by the nix-crypto plugin can be
   exported using `nix-crypto-service export secret`.
2. The public key derived from the exported private key matches the public key
   that the nix-crypto plugin computes via `openssl.public-key-pem`.

---

## Key files and their roles

### `crypto/openssl/main.nix`
- Defines the `private-key` function which is the main entry point for working
  with OpenSSL private keys in nix.
- `private-key` accepts a `key-spec` with two fields:
  - `attrs`: an attribute set of key-value pairs used to construct the key
    identity string (e.g. `{ vault = "openssl"; name = "openssl-test-key"; }`).
  - `type`: the key type string (e.g. `"rsa"`).
- Internally, `to-key-identity` sorts the keys of `attrs` alphabetically and
  joins them as `key=value` pairs separated by `&`. For example:
  `{ vault = "openssl"; name = "openssl-test-key"; }` becomes
  `"name=openssl-test-key&vault=openssl"`.
- The `key-ref` passed to the plugin contains:
  - `key-identity`: the result of `to-key-identity attrs`.
  - `key-type`: the value of `key-spec.type`.
- The returned attribute set exposes:
  - `identity`: the key identity string (added as part of this feature).
  - `public-key-pem`: the public key in PEM format, computed by the nix plugin.
  - `x509`: a function to build X.509 certificates signed by this key.

### `crypto/openssl/default.nix`
- Wires together `main.nix`, `x509-params-type.nix`, and
  `private-key-spec-type.nix` using `lib.makeScope`.

### `crypto/openssl/private-key-spec-type.nix`
- Defines the NixOS module type for a private key spec.
- Fields:
  - `attrs`: `types.attrsOf types.str` — the key identity attribute set.
  - `type`: `types.oneOf [ (types.strMatching "rsa") ]` — the key type.

### `crypto/openssl/x509-params-type.nix`
- Defines the NixOS module type for X.509 certificate build parameters.
- Fields:
  - `subject-public-key`: `types.nullOr types.str` (optional).
  - `subject-name`: `types.attrsOf types.str`.
  - `issuer-name`: `types.attrsOf types.str`.
  - `serial`: `types.int`.
  - `start-date`: `types.str` (RFC3339 intended).
  - `expiry-date`: `types.str` (RFC3339 intended).
  - `basic-constraints`: `types.nullOr basicConstraintsType` (optional).
  - `key-usage`: `types.nullOr keyUsageType` (optional).

### `crypto/default.nix`
- Top-level crypto library. Guards usage behind a check for `builtins.crypto`
  (which is only available when the nix-crypto plugin is loaded).
- Exposes `openssl` (and other future modules) via `lib.makeScope`.

### `nix-crypto-service/src/main.rs`
- CLI entry point for `nix-crypto-service`.
- Uses `docopt` for argument parsing.
- Supports the subcommand `export secret` with the following flags:
  - `--sled-store <path>`: path to the sled store (optional if
    `NIX_CRYPTO_STORE=sled:<path>` is set in the environment).
  - `--identity-type <type>`: the identity type. Currently only `openssl-pkey`
    is supported.
  - `--openssl-pkey-type <type>`: the OpenSSL key type (e.g. `rsa`). Required
    when `--identity-type` is `openssl-pkey`.
  - `--openssl-pkey-id <id>`: the OpenSSL key identity string (e.g.
    `name=openssl-test-key&vault=openssl`). Required when `--identity-type` is
    `openssl-pkey`.
  - `--output-file <path>`: the file to write the exported PEM private key to.

### `nix-crypto-service/src/export.rs`
- Implements the `export secret` subcommand.
- `resolve_sled_store`: resolves the sled store path from `--sled-store` flag
  or from the `NIX_CRYPTO_STORE=sled:<path>` environment variable.
- `resolve_identity_type`: resolves the identity type from flags.
- `resolve_args`: combines the above into an `ExportArgs` struct.
- `run_secret`:
  - Constructs a `CryptoNix` instance from the sled config.
  - Calls `crypto_nix.openssl_private_key(&identity)` to obtain (or generate)
    the private key.
  - Converts the key to PEM using `key.key_to_pem()`.
  - Writes the PEM to the output file.
- `OpensslPkeyIdentity`: a local struct implementing both `IsCryptoStoreKey`
  and `IsOpensslPrivateKeyIdentity`, delegating to `pkey_store_helpers`.

### `test/openssl.nix`
- The test suite for OpenSSL functionality.
- Uses `pkgs.callPackage ../crypto/default.nix {}` to get the crypto library.
- Defines `pk-rsa` as:
  ```nix
  openssl.private-key {
    attrs = { vault = "openssl"; name = "openssl-test-key"; };
    type = "rsa";
  }
  ```
- The "It can export the private key" test:
  - Uses `pk-rsa.public-key-pem` as the expected public key.
  - Uses `pk-rsa.identity` as the key identity string passed to
    `nix-crypto-service`.
  - Writes the expected public key to a temp file.
  - Calls `nix-crypto-service export secret` with `$STORE` (set by the test
    runner) as the sled store path.
  - Uses `openssl pkey -in <private key file> -pubout` to derive the public key
    from the exported private key.
  - Uses `diff` to compare the derived public key with the expected public key.

### `test/main.nix`
- The test runner. Accepts `pkgs` and `nix-crypto-service` as parameters.
- Defines `_assert`, a per-test assertion library with:
  - `_assert <cond> <message>`: assert a nix boolean expression.
  - `_assert.is-string <value>`: assert a value is a string.
  - `_assert.is-int <value>`: assert a value is an int.
  - `_assert.strings.has-prefix <prefix> <value>`: assert a string has a prefix.
  - `_assert.bash-script <script>`: run a bash script as a test. The script
    should exit with non-zero status on failure.
- `write-unit-test`: uses `pkgs.writeShellApplication` (not `pkgs.writeScript`)
  so that all test derivations expose their binary consistently under
  `$out/bin/<name>`. This is important because `run-tests` invokes all tests
  as `${test}/bin/${test.name}`.
- `test-bash-script`: wraps a bash script in a `pkgs.writeShellApplication`
  derivation. The script is run in a subshell; success/failure is reported with
  a ✓/✗ prefix.
- `run-tests`: iterates over tests, running each via `${test}/bin/${test.name}`.
  This works consistently for all tests because both `write-unit-test` and
  `test-bash-script` use `writeShellApplication`.
- `run-suite`: imports a suite file, passing `{ pkgs, nix-crypto-service }` as
  the suite context.
- `run-suites`: produces a `writeShellApplication` that runs all suites and
  exits with non-zero status if any test fails.

### `test/main-dev.nix`
- Entry point for running tests in the dev shell.
- Accepts `system`, `nixpkgs`, and optionally `nix-crypto-service` (defaults to
  `"$PWD/target/debug/nix-crypto-service"`).
- Calls `./main.nix` with the resolved parameters.

### `flakeModule.nix`
- Wires everything together for the flake.
- `test-dev` (the `nix-crypto-check` script):
  - Sets `STORE` to a temp directory.
  - Runs the nix plugin from `$PWD/target/debug/libnix_crypto_plugin.so`.
  - Passes `nix-crypto-service = "$PWD/target/debug/nix-crypto-service"` to
    `test/main-dev.nix` as a string (dev binary, not store package).
- `config.checks."cryptonix"` (prod test suite):
  - Passes `nix-crypto-service = "${nix-crypto.packages.nix-crypto-service}/bin/nix-crypto-service"`
    to `test/main-dev.nix` (store-built package).

### `nix-crypto.nix`
- Builds both `nix-crypto-plugin` and `nix-crypto-service` using
  `rustPlatform.buildRustPackage`.
- `nix-crypto-service` build inputs: `openssl`, `cargo`.
- Exports `packages = { nix-crypto-plugin, nix-crypto, nix-crypto-service, default = nix-crypto }`.

---

## Key design decisions

### `identity` field on private keys
- Added to `crypto/openssl/main.nix` so that callers do not need to manually
  reconstruct the identity string.
- Set to `key-ref.key-identity`, which is the result of `to-key-identity
  key-spec.attrs`.
- This mirrors the existing `public-key-pem` field in terms of how it is
  exposed.

### `STORE` environment variable
- The test runner (`test-dev` in `flakeModule.nix` and the prod test suite)
  sets `STORE` to a temp directory before invoking the nix evaluator.
- The nix plugin is configured with `mode=filesystem&store-path=$STORE`.
- The bash script test reads `$STORE` to pass to `nix-crypto-service
  --sled-store`.
- This ensures both the plugin and the service use the same sled store, so the
  key generated by the plugin can be exported by the service.

### `nix-crypto-service` as a string vs. a derivation
- In dev (`test-dev`), `nix-crypto-service` is passed as a plain string path
  (`$PWD/target/debug/nix-crypto-service`) so that the dev binary is used
  without requiring a nix build.
- In prod (`config.checks."cryptonix"`), it is passed as the store path of the
  built derivation.
- Both cases work because the bash script test simply interpolates
  `${nix-crypto-service}` directly into the script.

### `bash-script` in `_assert`
- Added to support tests that cannot be expressed as pure nix expressions (e.g.
  tests that require running external binaries).
- Uses `pkgs.writeShellApplication` so that the test binary has a proper
  `bin/<name>` path, consistent with how `run-tests` invokes tests.

### `write-unit-test` uses `writeShellApplication`
- Previously used `pkgs.writeScript`, which produces a single script file at
  the store path root, not under `bin/`.
- Changed to `pkgs.writeShellApplication` so that all test derivations
  consistently expose their binary under `$out/bin/<name>`.
- This is required because `run-tests` invokes all tests as
  `${test}/bin/${test.name}`, which only works with `writeShellApplication`.

---

## Potential issues / things to watch out for

1. **Heredoc indentation**: The `cat > "$EXPECTED_PUBLIC_KEY_FILE" << 'EOF'`
   block in the bash script test uses nix string interpolation for
   `${expected-public-key-pem}`. Care must be taken that the PEM content is not
   indented (which would corrupt it). The heredoc uses a literal `EOF` (not
   `<<- EOF`) so indentation of the content matters.

2. **`openssl` binary availability**: The bash script test calls `openssl pkey`.
   The `openssl` binary must be available in `PATH` when the test runs. In the
   prod VM test, this may need to be added to `runtimeInputs` of the
   `writeShellApplication` wrapping the test suite, or installed in the VM's
   `environment.systemPackages`.

3. **Key identity string format**: The identity string produced by
   `to-key-identity` sorts keys alphabetically. For
   `{ vault = "openssl"; name = "openssl-test-key"; }`, this produces
   `"name=openssl-test-key&vault=openssl"`. This must match exactly what the
   nix plugin uses when storing the key, and what `nix-crypto-service` uses
   when looking it up.

4. **`STORE` must be the same for plugin and service**: If the plugin and the
   service use different store paths, the service will not find the key. The
   test runner is responsible for ensuring both use the same `$STORE`.

5. **`writeShellApplication` name sanitisation**: `pkgs.writeShellApplication`
   uses the `name` field as both the derivation name and the binary name. Test
   names like `"It can export the private key"` contain spaces, which may cause
   issues. This should be verified — it may be necessary to sanitise test names
   (e.g. replacing spaces with hyphens) before passing them to
   `writeShellApplication`.
