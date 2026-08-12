{ ... }:
let
  x = 42;
in
  {
    config.development-tools.presets.prelude.neovim.editor.enable = true;
    config.development-tools.neovim.editor = {
      plugins.telescope.globals.file-ignore-patterns = [
        "flake.lock"
        "journal/*"
        "doc/*"
        "Cargo.lock"
        "LICENSE"
      ];
    };
  }
