{ self, lib, flake-parts-lib, ... }:
let
  nixpkgs = self.inputs.nixpkgs;
  inherit (flake-parts-lib)
    mkPerSystemOption;
  inherit (lib)
    mkOption
    types;
in
{
  options.perSystem = mkPerSystemOption ({ pkgs, system, config, ... }:
  let
    nix-crypto = pkgs.callPackage ./nix-crypto.nix {};

    args = ''{ system = \"${system}\"; nixpkgs = \"${nixpkgs}\"; }'';

    nix-crypto-dev = pkgs.writeScriptBin "nix-crypto" ''
      STORE=$(mktemp -d)
      nix \
        --extra-experimental-features nix-command \
        --option plugin-files "$PWD/target/debug/libnix_crypto.so" \
        --option extra-cryptonix-args "mode=filesystem&store-path=$STORE" \
        "$@"
    '';

    # Utility command used to run the checks in the dev environment
    # using the library built with cargo. During dev, using
    # 'nix flake check' is slow as it must rebuild all rust dependencies
    # and the qemu vm.
    test-dev = pkgs.writeScriptBin "nix-crypto-check" ''
      STORE=$(mktemp -d)
      nix \
        --extra-experimental-features nix-command \
        --option plugin-files "$PWD/target/debug/libnix_crypto_plugin.so" \
        --option extra-cryptonix-args "mode=filesystem&store-path=$STORE" \
        eval --show-trace --impure --expr "import \"$PWD/test/main-dev.nix\" ${args}"
    '';
  in
    {
      config.packages = nix-crypto.packages;
      config.devShells.default =
        pkgs.mkShell {
          buildInputs =
            with pkgs;
            with pkgs.nixVersions.nixComponents_2_31; [
              nix-crypto-dev
              test-dev
              cmake
              pkg-config
              nix-store
              nix-expr
              nix-cmd
              nix-fetchers
              boost
              cargo
              nixVersions.nix_2_31
            ]
          ;
        }
      ;
      config.checks."cryptonix" =
        let
          make-test = import "${self.inputs.nixpkgs}/nixos/tests/make-test-python.nix";
          test-suite =
            pkgs.writeShellApplication {
              name = "nix-crypto-tests";
              runtimeInputs = [ nix-crypto.packages.nix-crypto ];
              text = ''
                STORE=$(mktemp -d)
                cd ${./.}
                nix \
                  --extra-experimental-features nix-command \
                  --option extra-cryptonix-args "mode=filesystem&store-path=$STORE" \
                  eval --impure --expr "import ./test/main-dev.nix ${args}"
              '';
            }
          ;
        in
          make-test
          ({ pkgs, ... }: 
            {
              name = "nix-crypto test vm";
              nodes.machine = {
                environment.systemPackages = [ test-suite ];
              };

              testScript = ''
                machine.start()
                machine.wait_for_unit("multi-user.target")

                machine.succeed("nix-crypto-tests")
              '';
            }
          )
          { inherit system pkgs; }
      ;
    }
  );
}
