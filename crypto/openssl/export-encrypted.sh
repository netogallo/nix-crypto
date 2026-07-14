key=""
out_file=""
# shellcheck disable=SC2034
verbose_name="decrypt"
eval "$(docopts -V - -h - : "$@" <<EOF
Usage:
    decrypt --key <file> --out-file <file> [--skip-cleanup] [--verbose]
    decrypt --help
    decrypt --version

Options:
    --verbose                 Generate verbose messages.
    --help                    Show help options.
    --version                 Print program version.
    --skip-cleanup            Do not clean temporary directories after exit. Use with caution as private cryptographic credentials will be left behind.
    --key <file>              The private key that will be used to decrypt the credential.
    --out-file <file>         The file where the plaintext will be saved.
----
Nix Crypto ${nix-crypto-version}
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
EOF
)"

# shellcheck disable=SC1091
source "${decrypt-common}"

echo_verbose "The working directory is: $WORKDIR"

ephemeral_key="$WORKDIR/ephemeral_key.bin"
exec_verbose ${ephemeral-key-envelope.decrypt} --key "$key" --out-file "$ephemeral_key" "''${skip_cleanup:+--skip-cleanup}" "''${verbose:+--verbose}"
echo_verbose "Saved ephemeral key to: $ephemeral_key"

exec_verbose ${payload-envelope.decrypt} --key "$ephemeral_key" --out-file "$out_file" "''${skip_cleanup:+--skip-cleanup}" "''${verbose:+--verbose}"
