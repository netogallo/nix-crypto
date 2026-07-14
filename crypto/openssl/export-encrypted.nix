{
  pkgs,
  prelude,
  callPackage,
  self-key-ref,
  encryption-key-ref,
  nix-crypto-version,
  ...
}:
let
  inherit (pkgs) lib;
  inherit (builtins.crypto) openssl;
  inherit (pkgs.tikal.prelude.template) template;
  self = openssl.export-encrypted-pkey-pkey self-key-ref encryption-key-ref;
  ephemeral-key-envelope = callPackage ./envelope.nix {
    self = self.encrypted-ephemeral-key;
  };
  payload-envelope = callPackage ./envelope.nix {
    self = self.encrypted-payload;
  };
  decrypt-application = pkgs.writeShellApplication {
    name = "decrypt";
    runtimeInputs = with pkgs; [ docopts pkgs.openssl tinyxxd coreutils ];
    text = template ./export-encrypted.sh {
      inherit nix-crypto-version ephemeral-key-envelope
        payload-envelope;
      decrypt-common = ./decrypt-common.sh;
    };
  };
in
  {
    inherit self decrypt-application;
    decrypt = "${decrypt-application}/bin/${decrypt-application.NIX_MAIN_PROGRAM}";
  }
