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

    test-args-base = ''{ system = \"${system}\"; nixpkgs = \"${nixpkgs}\"; }'';
    test-args-dev = ''(${test-args-base} // { nix-crypto-service = \"$PWD/target/debug/nix-crypto-service\"; })'';
    test-args-uat = ''(${test-args-base} // { nix-crypto-service = \"nix-crypto-service\"; })'';
    nix-crypto-args = "mode=filesystem&store-path=$NIX_CRYPTO_STORE&log-file=$NIX_CRYPTO_LOG&log-level=debug";
    nix-crypto-dev = pkgs.writeScriptBin "nix-crypto" ''
      nix \
        --extra-experimental-features nix-command \
        --option plugin-files "$PWD/target/debug/libnix_crypto.so" \
        --option extra-cryptonix-args "${nix-crypto-args}" \
        "$@"
    '';

    test-any =
    { test-expr
    , nix-crypto-store ? null
    , nix-crypto-log ? null
    , runtimeEnv ? {}
    , runtimeInputs ? []
    , nix-crypto-plugin ? null
    }:
    let
      plugin-arg =
        if nix-crypto-plugin != null
        then ''--option plugin-files "${nix-crypto-plugin}"''
        else ""
      ;
      store-var =
        if nix-crypto-store != null
        then "NIX_CRYPTO_STORE=${nix-crypto-store}"
        else ""
      ;
      log-var =
        if nix-crypto-store != null
        then "NIX_CRYPTO_LOG=${nix-crypto-log}"
        else ""
      ;
    in
      pkgs.writeShellApplication {
        name = "nix-crypto-check";
        inherit runtimeInputs runtimeEnv;
        text =
          ''
          ${store-var}
          ${log-var}
          OUT=$(mktemp -d)
          echo "The cwd: $PWD" >&2
          nix \
            --extra-experimental-features nix-command ${plugin-arg} \
            --option extra-cryptonix-args "${nix-crypto-args}" \
            --offline \
            build \
            --show-trace --impure \
            --expr "${test-expr}" \
            -o "$OUT/result"

          if ! (
            NIX_CRYPTO_STORE="$NIX_CRYPTO_STORE" \
            NIX_CRYPTO_LOG="$NIX_CRYPTO_LOG" \
            sh "$OUT/result/bin/nix-crypto-test-outcome"
          ); then
            cat "$NIX_CRYPTO_LOG"
            exit 1
          fi
          ''
        ;
      }
    ;

    # Utility command used to run the checks in the dev environment
    # using the library built with cargo. During dev, using
    # 'nix flake check' is slow as it must rebuild all rust dependencies
    # and the qemu vm.
    test-dev = test-any {
      test-expr = ''import \"$PWD/test/main-dev.nix\" ${test-args-dev}'';
      nix-crypto-plugin = "$PWD/target/debug/libnix_crypto_plugin.so";
    };
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
          shellHook = ''
          export NIX_CRYPTO_STORE=$(mktemp -d)
          export NIX_CRYPTO_LOG=$(mktemp)
          '';
        }
      ;
      config.checks."cryptonix" =
        let
          make-test = import "${self.inputs.nixpkgs}/nixos/tests/make-test-python.nix";
          test-suite = test-any {
            test-expr = ''import ./test/main-dev.nix ${test-args-uat}'';
            runtimeInputs = [
              nix-crypto.packages.nix-crypto
              nix-crypto.packages.nix-crypto-service
              pkgs.openssl
            ];
            nix-crypto-store = "$(mktemp -d)";
            nix-crypto-log = "$(mktemp)";
          };
          test-main =
            pkgs.writeShellApplication {
              name = "test-main";
              runtimeInputs = [ test-suite ];
              text =
                ''
                echo "The test cwd: '${./.}'" >&2
                (cd "${./.}" && ${test-suite.NIX_MAIN_PROGRAM})
                ''
              ;
            }
          ;
        in
          make-test
          ({ pkgs, ... }: 
            {
              name = "nix-crypto test vm";

              /*
              The VM cannot access the nix cache nor netowrk. Therefore
              all dependencies must be included beforehand. However, it is
              not sufficient to simply add the system packages. The derivations
              also need to be present in the store as the tests are running
              with the "--impure" flag.
              Todo: It should be possible to run w/o the "--impure" flag.
              */
              nodes.machine = {
                virtualisation.additionalPaths = with pkgs; [
                  stdenv.drvPath
                  gnu-config.drvPath
                ];
                environment.systemPackages = with pkgs; [
                  test-main
                  stdenv
                  gnu-config
                ];
              };

              testScript = ''
                machine.start()
                machine.wait_for_unit("multi-user.target")

                machine.succeed("${test-main.NIX_MAIN_PROGRAM}")
              '';
            }
          )
          { inherit system pkgs; }
      ;
    }
  );
}
