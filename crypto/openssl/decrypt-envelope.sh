verbose=0
verbose_name="decrypt_envelope"
skip_cleanup=0
key=""
in_file=""
out_file=""
eval "$(docopts -V - -h - : "$@" <<EOF
Usage:
    decrypt_envelope rsa --key <file> --in-file <file> --out-file <file> [--skip-cleanup] [--verbose]
    decrypt_envelope aes_iv --key <file> --iv <base64 string> --in-file <file> --out-file <file> [--skip-cleanup] [--verbose]
    decrypt_envelope --help
    decrypt_envelope --version

Options:
    --verbose                 Generate verbose messages.
    --help                    Show help options.
    --version                 Print program version.
    --skip-cleanup            Do not clean temporary directories after exit. Use with caution as private cryptographic credentials will be left behind.
    --key <file>              The private key that will be used to decrypt the credential.
    --in-file <file>          The ciphertext file to be decrypted.
    --out-file <file>         The file where the decrypted plaintext will be saved.
    --iv <base64 string>      The file containing the initialization vector.
----
Nix Crypto ${nix-crypto-version}
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
EOF
)"

source "${decrypt-common}"

decrypt_rsa() {

  ciphertext_bin="$WORKDIR/ciphertext.bin"
  cat "$in_file" | base64 -d | (cat > "$ciphertext_bin")
  
  echo_verbose "[RSA] Wrote the binary ciphertext to $ciphertext_bin"
  
  exec_verbose openssl pkeyutl -decrypt \
    -inkey "$key" \
    -in "$ciphertext_bin" \
    -out "$out_file" \
    -pkeyopt "rsa_padding_mode:oaep"
}

decrypt_aes_iv() {

  # Convert the base64 ciphertext into binary
  ciphertext_bin="$WORKDIR/ciphertext.bin"
  cat "$in_file" | base64 -d | (cat > "$ciphertext_bin")
  echo_verbose "[AES] Wrote the binary ciphertext to $ciphertext_bin"

  # Convert the key into a hex representation
  key_hex="$WORKDIR/key_hex"
  cat "$key" | xxd -p -c 0 | (cat > "$key_hex")

  # Convert the iv into a hex representaiton
  iv_hex="$WORKDIR/iv_hex"
  echo "$iv" | base64 -d | xxd -p -c 0 | (cat > "$iv_hex")

  exec_verbose openssl enc -d -aes-256-cbc \
    -K "$(cat "$key_hex")" \
    -iv "$(cat "$iv_hex")" \
    -in "$ciphertext_bin" \
    -out "$out_file"
}

if $rsa; then
  decrypt_rsa
elif $aes_iv; then
  decrypt_aes_iv
fi

