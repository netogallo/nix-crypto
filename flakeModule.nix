{ self, lib, flake-parts-lib, ... }:
let
  inherit (flake-parts-lib)
    mkPerSystemOption;
  inherit (lib)
    mkOption
    types;
in
{
  options.perSystem = mkPerSystemOption ({ pkgs, config, ... }:
  let
    nix-crypto = pkgs.callPackage ./nix-crypto.nix {};
  in
    {
      config.tests = {
        "Dummy test" = {
          test = _: { success = true; message = ""; };
        };
      };
      config.packages = nix-crypto.packages;
      config.devShells.default =
        pkgs.mkShell {
          buildInputs =
            with pkgs;
            with pkgs.nixVersions.nixComponents_2_31; [
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
    }
  );
}
