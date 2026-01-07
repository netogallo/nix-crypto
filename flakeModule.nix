{ self, lib, flake-parts-lib, ... }:
let
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

    # Utility command used to run the checks in the dev environment
    # using the library built with cargo. During dev, using
    # 'nix flake check' is slow as it must rebuild all rust dependencies
    # and the qemu vm.
    test-dev = pkgs.writeScriptBin "nix-crypto-check" ''
      STORE=$(mktemp -d)
      nix \
        --extra-experimental-features nix-command \
        --option plugin-files "$PWD/target/debug/libnix_crypto.so" \
        --option extra-cryptonix-args "mode=filesystem&store-path=$STORE" \
        eval --impure --expr "import \"$PWD/test/main.nix\" {}"
    '';
  in
    {
      config.packages = nix-crypto.packages;
      config.devShells.default =
        pkgs.mkShell {
          buildInputs =
            with pkgs;
            with pkgs.nixVersions.nixComponents_2_31; [
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
                nix \
                  --extra-experimental-features nix-command \
                  --option extra-cryptonix-args "mode=filesystem&store-path=$STORE" \
                  eval --impure --expr 'import "${./test/main.nix}" {}'
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
