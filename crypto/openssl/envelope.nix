{
  self,
  pkgs,
  nix-crypto-version,
  ...
}:
let
  inherit (pkgs.tikal.prelude.trace-lib) debug-print;
  inherit (pkgs.tikal.prelude.template) template;
  inherit (pkgs.tikal.prelude) match;
  decrypt-envelope =
  let
    context = {
      inherit nix-crypto-version;
      decrypt-common = ./decrypt-common.sh;
    };
  in
    pkgs.writeScript
      "decrypt-envelope"
      (template ./decrypt-envelope.sh context)
  ;
  decrypt-rsa =
    {
      rsa-key-size,
      rsa-padding,
      rsa-ciphertext-base64
    }: 
    let
      ciphertext-base64 = pkgs.writeText "ciphertext-base64" rsa-ciphertext-base64;
      text = ''
        sh ${decrypt-envelope} rsa --in-file "${ciphertext-base64}" "$@"
      '';
      name = "decrypt_envelope";
    in
      pkgs.writeShellApplication {
        inherit name text;
      }
  ;
  decrypt-aes =
    {
      aes-key-size,
      aes-key-derivation,
      aes-mode,
      aes-ciphertext-base64
    }:
    let
      ciphertext-base64 = pkgs.writeText "ciphertext-base64" aes-ciphertext-base64;
      name = "decrypt_envelope";
      text-iv = { aes-iv-base64 }: ''
        sh ${decrypt-envelope} aes_iv --in-file "${ciphertext-base64}" --iv "${aes-iv-base64}" "$@" 
      '';
      text = text-iv aes-key-derivation.no-derivation;
    in
      pkgs.writeShellApplication {
        inherit name text;
      }
  ;
  decrypt-app =
    match self [
      ({ openssl-rsa-envelope }: decrypt-rsa openssl-rsa-envelope)
      ({ openssl-aes-envelope }: decrypt-aes openssl-aes-envelope)
    ]
  ;
  decrypt = "${decrypt-app}/bin/${decrypt-app.NIX_MAIN_PROGRAM}";
in
  {
    inherit self decrypt;
  }
