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
      x = 4;
    in
      {
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
